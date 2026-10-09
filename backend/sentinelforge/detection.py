from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    Alert,
    AlertEvidence,
    CorrelationGroup,
    DetectionRule,
    NormalizedEvent,
    RuleVersion,
)

ALLOWED_TOP_LEVEL = {
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "modified",
    "version",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
    "references",
    "investigation",
    "sentinelforge",
}
ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
ALLOWED_MODIFIERS = {"contains", "startswith", "endswith", "exists", "all"}
CONDITION_TOKENS = re.compile(r"\(|\)|\b(?:and|or|not)\b|[A-Za-z_][A-Za-z0-9_*]*", re.I)
WINDOW_PATTERN = re.compile(r"^(\d+)(s|m|h)$")


class RuleValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    path: Path
    raw: dict[str, Any]

    @property
    def id(self) -> str:
        return str(self.raw["id"])

    @property
    def title(self) -> str:
        return str(self.raw["title"])

    @property
    def severity(self) -> str:
        return str(self.raw["level"])

    @property
    def confidence(self) -> int:
        return int(self.raw.get("sentinelforge", {}).get("confidence", 70))

    @property
    def attack_tags(self) -> list[str]:
        tags: list[str] = []
        for tag in self.raw.get("tags", []):
            match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag), re.I)
            if match:
                tags.append(match.group(1).upper())
        return list(dict.fromkeys(tags))

    @property
    def correlation(self) -> dict[str, Any] | None:
        value = self.raw.get("sentinelforge", {}).get("correlation")
        return value if isinstance(value, dict) else None


def _parse_window(value: str) -> timedelta:
    match = WINDOW_PATTERN.fullmatch(value)
    if not match:
        raise RuleValidationError("time window must use an integer followed by s, m, or h")
    quantity = int(match.group(1))
    if quantity < 1:
        raise RuleValidationError("time window must be positive")
    unit = match.group(2)
    return {
        "s": timedelta(seconds=quantity),
        "m": timedelta(minutes=quantity),
        "h": timedelta(hours=quantity),
    }[unit]


def _selection_names(detection: dict[str, Any]) -> list[str]:
    return [name for name in detection if name != "condition"]


def _expand_condition_phrases(condition: str, selections: list[str]) -> str:
    phrase = re.compile(r"\b(1|all)\s+of\s+([A-Za-z_][A-Za-z0-9_*]*)", re.I)

    def replace(match: re.Match[str]) -> str:
        mode, pattern = match.group(1).lower(), match.group(2)
        names = [name for name in selections if fnmatch.fnmatchcase(name, pattern)]
        if not names:
            raise RuleValidationError(f"condition wildcard {pattern!r} matches no selections")
        operator = " and " if mode == "all" else " or "
        return "(" + operator.join(names) + ")"

    return phrase.sub(replace, condition)


class _ConditionParser:
    def __init__(self, condition: str, values: dict[str, bool]) -> None:
        expanded = _expand_condition_phrases(condition, list(values))
        self.tokens = CONDITION_TOKENS.findall(expanded)
        compact = re.sub(r"\s+", "", expanded)
        if "".join(self.tokens).lower() != compact.lower():
            raise RuleValidationError("condition contains unsupported syntax")
        self.values = values
        self.position = 0

    def parse(self) -> bool:
        value = self._or()
        if self.position != len(self.tokens):
            raise RuleValidationError(f"unexpected condition token {self.tokens[self.position]!r}")
        return value

    def _or(self) -> bool:
        value = self._and()
        while self._peek("or"):
            self.position += 1
            right = self._and()
            value = value or right
        return value

    def _and(self) -> bool:
        value = self._not()
        while self._peek("and"):
            self.position += 1
            right = self._not()
            value = value and right
        return value

    def _not(self) -> bool:
        if self._peek("not"):
            self.position += 1
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        if self.position >= len(self.tokens):
            raise RuleValidationError("incomplete condition")
        token = self.tokens[self.position]
        if token == "(":
            self.position += 1
            value = self._or()
            if self.position >= len(self.tokens) or self.tokens[self.position] != ")":
                raise RuleValidationError("unbalanced condition parentheses")
            self.position += 1
            return value
        if token.lower() in {"and", "or", "not"} or token == ")":
            raise RuleValidationError(f"unexpected condition token {token!r}")
        if token not in self.values:
            raise RuleValidationError(f"condition references unknown selection {token!r}")
        self.position += 1
        return self.values[token]

    def _peek(self, value: str) -> bool:
        return self.position < len(self.tokens) and self.tokens[self.position].lower() == value


def validate_rule(document: Any, path: Path = Path("<memory>")) -> RuleDefinition:
    if not isinstance(document, dict):
        raise RuleValidationError("rule document must be a YAML mapping")
    unknown = sorted(set(document) - ALLOWED_TOP_LEVEL)
    if unknown:
        raise RuleValidationError(f"unsupported top-level fields: {', '.join(unknown)}")
    for required in ("title", "id", "description", "logsource", "detection", "level"):
        if required not in document:
            raise RuleValidationError(f"missing required field: {required}")
    if not re.fullmatch(r"SF-[A-Z0-9-]{3,64}", str(document["id"])):
        raise RuleValidationError("id must use the SF-UPPERCASE-ID format")
    if document["level"] not in ALLOWED_LEVELS:
        raise RuleValidationError(f"unsupported severity: {document['level']!r}")
    if not isinstance(document["logsource"], dict):
        raise RuleValidationError("logsource must be a mapping")
    detection = document["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleValidationError("detection must be a mapping containing condition")
    if "timeframe" in detection:
        raise RuleValidationError(
            "Sigma timeframe is unsupported; use sentinelforge.correlation.within"
        )
    names = _selection_names(detection)
    if not names:
        raise RuleValidationError("detection must contain at least one selection")
    for name in names:
        selection = detection[name]
        if not isinstance(selection, dict) or not selection:
            raise RuleValidationError(f"selection {name!r} must be a non-empty mapping")
        for field, expected in selection.items():
            field_parts = field.split("|")
            if not field_parts[0] or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", field_parts[0]):
                raise RuleValidationError(f"invalid field path {field!r}")
            modifiers = field_parts[1:]
            unsupported = [modifier for modifier in modifiers if modifier not in ALLOWED_MODIFIERS]
            if unsupported:
                raise RuleValidationError(
                    f"unsupported modifier(s) on {field_parts[0]}: {', '.join(unsupported)}"
                )
            if "all" in modifiers and not isinstance(expected, list):
                raise RuleValidationError(f"{field!r} uses all but its value is not a list")
            operations = set(modifiers) & {"contains", "startswith", "endswith", "exists"}
            if len(operations) > 1:
                raise RuleValidationError(f"{field!r} combines incompatible modifiers")
            if "exists" in modifiers and not isinstance(expected, bool):
                raise RuleValidationError(f"{field!r} uses exists but its value is not boolean")
            values = expected if isinstance(expected, list) else [expected]
            if not values or not all(isinstance(item, str | int | bool) for item in values):
                raise RuleValidationError(
                    f"{field!r} values must be scalar or a non-empty scalar list"
                )
    condition = detection["condition"]
    if not isinstance(condition, str) or not condition.strip():
        raise RuleValidationError("condition must be a non-empty string")
    _ConditionParser(condition, dict.fromkeys(names, False)).parse()

    extension = document.get("sentinelforge", {})
    if not isinstance(extension, dict):
        raise RuleValidationError("sentinelforge extension must be a mapping")
    unknown_extension = sorted(set(extension) - {"confidence", "correlation", "enabled"})
    if unknown_extension:
        raise RuleValidationError(
            f"unsupported sentinelforge fields: {', '.join(unknown_extension)}"
        )
    confidence = extension.get("confidence", 70)
    if not isinstance(confidence, int) or not 0 <= confidence <= 100:
        raise RuleValidationError("sentinelforge.confidence must be an integer from 0 to 100")
    correlation = extension.get("correlation")
    if correlation is not None:
        _validate_correlation(correlation, names)
    false_positives = document.get("falsepositives", [])
    if not isinstance(false_positives, list) or not all(
        isinstance(item, str) for item in false_positives
    ):
        raise RuleValidationError("falsepositives must be a string list")
    return RuleDefinition(path=path, raw=document)


def _validate_correlation(correlation: Any, selections: list[str]) -> None:
    if not isinstance(correlation, dict):
        raise RuleValidationError("correlation must be a mapping")
    kind = correlation.get("type")
    allowed = {"type", "within", "group_by", "deduplicate", "selection", "count", "steps"}
    unknown = sorted(set(correlation) - allowed)
    if unknown:
        raise RuleValidationError(f"unsupported correlation fields: {', '.join(unknown)}")
    if kind not in {"threshold", "sequence"}:
        raise RuleValidationError("correlation.type must be threshold or sequence")
    _parse_window(str(correlation.get("within", "")))
    _parse_window(str(correlation.get("deduplicate", "5m")))
    group_by = correlation.get("group_by", [])
    if (
        not isinstance(group_by, list)
        or not group_by
        or not all(
            isinstance(item, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", item)
            for item in group_by
        )
    ):
        raise RuleValidationError("correlation.group_by must be a non-empty field-path list")
    if kind == "threshold":
        if correlation.get("selection") not in selections:
            raise RuleValidationError("threshold correlation references an unknown selection")
        count = correlation.get("count")
        if not isinstance(count, int) or not 2 <= count <= 10000:
            raise RuleValidationError("threshold count must be an integer from 2 to 10000")
    else:
        steps = correlation.get("steps")
        if not isinstance(steps, list) or not 2 <= len(steps) <= 20:
            raise RuleValidationError("sequence steps must contain 2 to 20 selection names")
        if any(step not in selections for step in steps):
            raise RuleValidationError("sequence references an unknown selection")


def load_rules(path: Path) -> tuple[list[RuleDefinition], list[str]]:
    rules: list[RuleDefinition] = []
    errors: list[str] = []
    if not path.exists():
        return [], [f"rule directory does not exist: {path}"]
    seen: set[str] = set()
    for rule_path in sorted((*path.glob("*.yml"), *path.glob("*.yaml"))):
        try:
            with rule_path.open("r", encoding="utf-8") as handle:
                document = yaml.safe_load(handle)
            rule = validate_rule(document, rule_path)
            if rule.id in seen:
                raise RuleValidationError(f"duplicate rule ID {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
        except (OSError, yaml.YAMLError, RuleValidationError) as exc:
            errors.append(f"{rule_path}: {exc}")
    return rules, errors


def _lookup(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        key = next((candidate for candidate in current if candidate.lower() == part.lower()), None)
        if key is None:
            return None
        current = current[key]
    return current


def _match_scalar(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if "exists" in modifiers:
        wanted = bool(expected)
        return (actual is not None) == wanted
    if actual is None:
        return False
    if isinstance(actual, str) and isinstance(expected, str):
        actual_value, expected_value = actual.casefold(), expected.casefold()
        if "contains" in modifiers:
            return expected_value in actual_value
        if "startswith" in modifiers:
            return actual_value.startswith(expected_value)
        if "endswith" in modifiers:
            return actual_value.endswith(expected_value)
        return actual_value == expected_value
    return actual == expected


def match_selection(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    for field_expression, expected in selection.items():
        field, *modifiers = field_expression.split("|")
        actual = _lookup(event, field)
        values = expected if isinstance(expected, list) else [expected]
        matches = [_match_scalar(actual, value, modifiers) for value in values]
        if ("all" in modifiers and not all(matches)) or (
            "all" not in modifiers and not any(matches)
        ):
            return False
    return True


def match_rule(event: dict[str, Any], rule: RuleDefinition) -> bool:
    detection = rule.raw["detection"]
    values = {
        name: match_selection(event, selection)
        for name, selection in detection.items()
        if name != "condition"
    }
    return _ConditionParser(detection["condition"], values).parse()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class DetectionEngine:
    def __init__(self, rules: list[RuleDefinition]) -> None:
        self.rules = rules

    def sync_catalog(self, session: Session) -> None:
        active_ids = {rule.id for rule in self.rules}
        for rule in self.rules:
            record = session.get(DetectionRule, rule.id)
            values = {
                "title": rule.title,
                "description": str(rule.raw["description"]),
                "version": int(rule.raw.get("version", 1)),
                "status": str(rule.raw.get("status", "experimental")),
                "severity": rule.severity,
                "confidence": rule.confidence,
                "enabled": bool(rule.raw.get("sentinelforge", {}).get("enabled", True)),
                "source_path": str(rule.path),
                "definition_json": rule.raw,
                "attack_tags": rule.attack_tags,
                "updated_at": datetime.now(UTC),
            }
            if record is None:
                session.add(DetectionRule(id=rule.id, **values))
            else:
                for key, value in values.items():
                    setattr(record, key, value)
            session.flush()
            canonical = json.dumps(rule.raw, sort_keys=True, separators=(",", ":"))
            definition_hash = hashlib.sha256(canonical.encode()).hexdigest()
            version_exists = session.scalar(
                select(RuleVersion.id).where(
                    RuleVersion.rule_id == rule.id,
                    RuleVersion.definition_hash == definition_hash,
                )
            )
            if version_exists is None:
                session.add(
                    RuleVersion(
                        rule_id=rule.id,
                        version=int(rule.raw.get("version", 1)),
                        definition_hash=definition_hash,
                        definition_json=rule.raw,
                    )
                )
        for record in session.scalars(select(DetectionRule)).all():
            if record.id not in active_ids:
                record.enabled = False

    def evaluate(self, session: Session, event: NormalizedEvent) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            catalog_rule = session.get(DetectionRule, rule.id)
            if catalog_rule is None or not catalog_rule.enabled:
                continue
            evidence = self._evidence_for_rule(session, event, rule)
            if not evidence:
                continue
            alert = self._create_alert(session, event, rule, evidence)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def _evidence_for_rule(
        self, session: Session, event: NormalizedEvent, rule: RuleDefinition
    ) -> list[NormalizedEvent]:
        correlation = rule.correlation
        if correlation is None:
            return [event] if match_rule(event.data_json, rule) else []
        within = _parse_window(correlation["within"])
        current_time = _as_utc(event.event_time)
        oldest = current_time - within
        candidates = list(
            session.scalars(
                select(NormalizedEvent)
                .where(
                    NormalizedEvent.host_id == event.host_id,
                    NormalizedEvent.event_time >= oldest,
                    NormalizedEvent.event_time <= event.event_time,
                )
                .order_by(NormalizedEvent.event_time, NormalizedEvent.id)
                .limit(10000)
            ).all()
        )
        group_fields = correlation["group_by"]
        current_group = tuple(_lookup(event.data_json, field) for field in group_fields)
        candidates = [
            candidate
            for candidate in candidates
            if tuple(_lookup(candidate.data_json, field) for field in group_fields) == current_group
        ]
        selections = rule.raw["detection"]
        if correlation["type"] == "threshold":
            selection = selections[correlation["selection"]]
            if not match_selection(event.data_json, selection):
                return []
            matching = [item for item in candidates if match_selection(item.data_json, selection)]
            return matching if len(matching) >= correlation["count"] else []
        steps: list[str] = correlation["steps"]
        if not match_selection(event.data_json, selections[steps[-1]]):
            return []
        matched: list[NormalizedEvent] = []
        step_index = 0
        for candidate in candidates:
            if candidate.id == event.id:
                break
            if match_selection(candidate.data_json, selections[steps[step_index]]):
                matched.append(candidate)
                step_index += 1
                if step_index == len(steps) - 1:
                    return [*matched, event]
        return []

    def _create_alert(
        self,
        session: Session,
        event: NormalizedEvent,
        rule: RuleDefinition,
        evidence: list[NormalizedEvent],
    ) -> Alert | None:
        correlation = rule.correlation or {}
        group_fields = correlation.get("group_by", ["host.hostname"])
        group_parts = [str(_lookup(event.data_json, field) or "-") for field in group_fields]
        group_key = "|".join(group_parts)
        deduplicate = _parse_window(correlation.get("deduplicate", "1m"))
        cutoff = datetime.now(UTC) - deduplicate
        existing = session.scalar(
            select(Alert).where(
                Alert.rule_id == rule.id,
                Alert.group_key == group_key,
                Alert.created_at >= cutoff,
            )
        )
        if existing is not None:
            return None
        evidence_ids = [item.id for item in evidence]
        digest = hashlib.sha256(
            json.dumps([rule.id, group_key, evidence_ids], separators=(",", ":")).encode()
        ).hexdigest()
        first_time = min(_as_utc(item.event_time) for item in evidence)
        last_time = max(_as_utc(item.event_time) for item in evidence)
        correlation_description = (
            f"{correlation['type']} correlation matched {len(evidence)} events"
            if correlation
            else "event matched the Sigma selection and condition"
        )
        alert = Alert(
            rule_id=rule.id,
            host_id=event.host_id,
            scenario_run_id=event.scenario_run_id,
            severity=rule.severity,
            confidence=rule.confidence,
            title=rule.title,
            why=f"{correlation_description}; group={group_key}",
            investigation=str(
                rule.raw.get(
                    "investigation",
                    "Review the process lineage and adjacent host activity before disposition.",
                )
            ),
            false_positives=list(rule.raw.get("falsepositives", [])),
            attack_tags=rule.attack_tags,
            group_key=group_key,
            dedup_key=digest,
            first_event_time=first_time,
            last_event_time=last_time,
        )
        session.add(alert)
        session.flush()
        for position, matched_event in enumerate(evidence):
            session.add(
                AlertEvidence(
                    alert_id=alert.id,
                    event_id=matched_event.id,
                    position=position,
                    reason=(
                        f"Evidence {position + 1} satisfied {rule.id}; "
                        f"event_type={matched_event.event_type}"
                    ),
                )
            )
        if correlation:
            session.add(
                CorrelationGroup(
                    rule_id=rule.id,
                    group_key=group_key,
                    first_seen_at=first_time,
                    last_seen_at=last_time,
                    event_count=len(evidence),
                    closed=True,
                    state_json={"evidence_event_ids": evidence_ids},
                )
            )
        session.flush()
        return alert
