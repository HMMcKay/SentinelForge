from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import cast, delete, func, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from .detection import DetectionEngine
from .models import (
    Alert,
    AlertEvidence,
    AttackTechnique,
    DetectionRule,
    FileActivity,
    Host,
    IngestBatch,
    NetworkActivity,
    NormalizedEvent,
    ProcessActivity,
    RawEvent,
    RegistryActivity,
    Scenario,
    ScenarioRun,
    Sensor,
    utcnow,
)
from .schemas import EventBatchIn, NormalizedEventIn

SCENARIOS = [
    {
        "id": "registry-run-key",
        "name": "Registry run-key simulation",
        "description": "Writes and removes a benign value beneath a lab-scoped Run key.",
        "technique_ids": ["T1547.001"],
        "supported_platforms": ["windows"],
        "safety_notes": ["Lab mode is required", "Cleanup removes only the named test value"],
    },
    {
        "id": "scheduled-task",
        "name": "Scheduled task simulation",
        "description": "Creates a disabled, one-shot task that launches a benign lab command.",
        "technique_ids": ["T1053.005"],
        "supported_platforms": ["windows"],
        "safety_notes": ["Uses the SentinelForge task namespace", "Cleanup deletes the task"],
    },
    {
        "id": "benign-process-chain",
        "name": "Benign process chain",
        "description": (
            "Builds a deterministic parent/child process lineage without changing the host."
        ),
        "technique_ids": ["T1059.003"],
        "supported_platforms": ["windows", "synthetic"],
        "safety_notes": ["Commands print fixed strings only"],
    },
    {
        "id": "encoded-powershell",
        "name": "Encoded PowerShell benign execution",
        "description": (
            "Runs an encoded command that writes a marker inside the simulation sandbox."
        ),
        "technique_ids": ["T1059.001", "T1027.010"],
        "supported_platforms": ["windows", "synthetic"],
        "safety_notes": ["Payload is fixed", "Marker is included in the cleanup manifest"],
    },
    {
        "id": "user-writable-execution",
        "name": "User-writable execution",
        "description": "Executes a benign artifact from the dedicated simulation sandbox.",
        "technique_ids": ["T1204.002"],
        "supported_platforms": ["windows", "synthetic"],
        "safety_notes": ["Artifact is generated locally and contains no external payload"],
    },
    {
        "id": "dns-localhost",
        "name": "DNS and localhost interaction",
        "description": "Queries a reserved test name and connects only to loopback.",
        "technique_ids": ["T1071.004"],
        "supported_platforms": ["windows", "synthetic"],
        "safety_notes": ["No non-loopback connection is allowed"],
    },
    {
        "id": "ransomware-emulator",
        "name": "Synthetic ransomware behavior",
        "description": "Renames and rewrites generated synthetic files, then restores them.",
        "technique_ids": ["T1486"],
        "supported_platforms": ["windows", "synthetic"],
        "safety_notes": [
            "Refuses paths outside the sandbox",
            "Original hashes are verified on cleanup",
        ],
    },
    {
        "id": "security-control-events",
        "name": "Synthetic security-control modification",
        "description": "Emits telemetry representing control changes without modifying a control.",
        "technique_ids": ["T1685"],
        "supported_platforms": ["synthetic"],
        "safety_notes": ["No operating-system control is modified"],
    },
]

TECHNIQUES = {
    "T1027.010": ("Obfuscated Files or Information: Command Obfuscation", "Stealth"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    "T1547.001": (
        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "Persistence",
    ),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1685": ("Disable or Modify Tools", "Defense Impairment"),
}


def seed_catalog(session: Session) -> None:
    for item in SCENARIOS:
        record = session.get(Scenario, item["id"])
        if record is None:
            session.add(Scenario(**item))
        else:
            for key, value in item.items():
                if key != "id":
                    setattr(record, key, value)
    for technique_id, (name, tactic) in TECHNIQUES.items():
        record = session.get(AttackTechnique, technique_id)
        values = {
            "name": name,
            "tactic": tactic,
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        }
        if record is None:
            session.add(AttackTechnique(id=technique_id, **values))
        else:
            for key, value in values.items():
                setattr(record, key, value)


def ensure_host(session: Session, sensor: Sensor, event: NormalizedEventIn) -> Host:
    host = session.scalar(
        select(Host).where(Host.sensor_id == sensor.id, Host.hostname == event.host.hostname)
    )
    if host is None:
        host = Host(
            sensor_id=sensor.id,
            hostname=event.host.hostname,
            os_name=event.host.os_name,
            os_version=event.host.os_version,
            last_seen_at=event.event_time,
        )
        session.add(host)
        session.flush()
    else:
        host.last_seen_at = max(_aware(host.last_seen_at), event.event_time)
        if event.host.os_name:
            host.os_name = event.host.os_name
        if event.host.os_version:
            host.os_version = event.host.os_version
    return host


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def persist_event(
    session: Session,
    sensor: Sensor,
    schema_version: str,
    event: NormalizedEventIn,
) -> NormalizedEvent | None:
    duplicate = session.scalar(
        select(NormalizedEvent.id).where(
            NormalizedEvent.sensor_id == sensor.id,
            NormalizedEvent.source_event_id == event.event_id,
        )
    )
    if duplicate is not None:
        return None
    if event.scenario_run_id and session.get(ScenarioRun, event.scenario_run_id) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"unknown scenario_run_id: {event.scenario_run_id}",
        )
    host = ensure_host(session, sensor, event)
    payload = event.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    raw = RawEvent(
        sensor_id=sensor.id,
        host_id=host.id,
        source_event_id=event.event_id,
        event_time=event.event_time,
        payload_sha256=hashlib.sha256(canonical.encode()).hexdigest(),
        payload_json=payload,
    )
    session.add(raw)
    session.flush()
    normalized = NormalizedEvent(
        schema_version=schema_version,
        sensor_id=sensor.id,
        host_id=host.id,
        raw_event_id=raw.id,
        source_event_id=event.event_id,
        event_time=event.event_time,
        event_type=event.event_type,
        process_guid=event.process.guid if event.process else None,
        parent_process_guid=event.process.parent_guid if event.process else None,
        scenario_run_id=event.scenario_run_id,
        attack_tags=event.attack_tags,
        data_json=payload,
    )
    session.add(normalized)
    session.flush()
    if event.process:
        session.add(
            ProcessActivity(
                event_id=normalized.id,
                process_guid=event.process.guid,
                parent_process_guid=event.process.parent_guid,
                pid=event.process.pid,
                image=event.process.executable,
                command_line=event.process.command_line,
                user_name=event.user.name if event.user else None,
            )
        )
    if event.network:
        session.add(
            NetworkActivity(
                event_id=normalized.id,
                destination_ip=event.network.destination_ip,
                destination_port=event.network.destination_port,
                protocol=event.network.protocol,
                dns_question=event.network.dns_question,
            )
        )
    if event.file:
        session.add(
            FileActivity(
                event_id=normalized.id,
                path=event.file.path,
                operation=event.file.operation,
                sha256=event.file.sha256,
            )
        )
    if event.registry:
        session.add(
            RegistryActivity(
                event_id=normalized.id,
                key_path=event.registry.key_path,
                value_name=event.registry.value_name,
                value_data=event.registry.value_data,
                operation=event.registry.operation,
            )
        )
    session.flush()
    return normalized


def ingest_batch(
    session: Session,
    sensor: Sensor,
    payload: EventBatchIn,
    engine: DetectionEngine,
) -> tuple[dict[str, Any], list[Alert]]:
    if payload.sensor_id != sensor.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="sensor_id does not match token"
        )
    prior = session.scalar(
        select(IngestBatch).where(
            IngestBatch.sensor_id == sensor.id, IngestBatch.batch_id == payload.batch_id
        )
    )
    if prior:
        return (
            {
                "batch_id": prior.batch_id,
                "accepted": prior.accepted_count,
                "duplicates": prior.duplicate_count,
                "alerts_created": prior.alert_count,
                "idempotent_replay": True,
            },
            [],
        )
    batch = IngestBatch(
        sensor_id=sensor.id,
        batch_id=payload.batch_id,
        schema_version=payload.schema_version,
    )
    session.add(batch)
    session.flush()
    accepted = 0
    duplicates = 0
    alerts: list[Alert] = []
    seen_in_batch: set[str] = set()
    for incoming in payload.events:
        if incoming.event_id in seen_in_batch:
            duplicates += 1
            continue
        seen_in_batch.add(incoming.event_id)
        stored = persist_event(session, sensor, payload.schema_version, incoming)
        if stored is None:
            duplicates += 1
            continue
        accepted += 1
        alerts.extend(engine.evaluate(session, stored))
    sensor.last_seen_at = utcnow()
    batch.accepted_count = accepted
    batch.duplicate_count = duplicates
    batch.alert_count = len(alerts)
    session.flush()
    return (
        {
            "batch_id": payload.batch_id,
            "accepted": accepted,
            "duplicates": duplicates,
            "alerts_created": len(alerts),
            "idempotent_replay": False,
        },
        alerts,
    )


def serialize_event(event: NormalizedEvent) -> dict[str, Any]:
    host = event.data_json.get("host", {})
    user = event.data_json.get("user")
    process = event.data_json.get("process")
    category = event.event_type.split("_", 1)[0]
    return {
        "id": event.id,
        "source_event_id": event.source_event_id,
        "schema_version": event.schema_version,
        "sensor_id": event.sensor_id,
        "host_id": event.host_id,
        "raw_event_id": event.raw_event_id,
        "event_time": _aware(event.event_time).isoformat(),
        "ingest_time": _aware(event.ingest_time).isoformat(),
        "ingested_at": _aware(event.ingest_time).isoformat(),
        "event_type": event.event_type,
        "category": category,
        "action": event.event_type,
        "host": {"id": event.host_id, **host},
        "hostname": host.get("hostname"),
        "user": user,
        "user_info": user,
        "process": process,
        "network": event.data_json.get("network"),
        "file": event.data_json.get("file"),
        "registry": event.data_json.get("registry"),
        "process_guid": event.process_guid,
        "parent_process_guid": event.parent_process_guid,
        "scenario_run_id": event.scenario_run_id,
        "attack_tags": event.attack_tags,
        "techniques": event.attack_tags,
        "metadata": event.data_json.get("metadata", {}),
        "data": event.data_json,
    }


def serialize_alert(
    session: Session, alert: Alert, include_evidence: bool = True
) -> dict[str, Any]:
    host = session.get(Host, alert.host_id)
    result: dict[str, Any] = {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "host_id": alert.host_id,
        "host": (
            {"id": host.id, "hostname": host.hostname, "name": host.hostname} if host else None
        ),
        "scenario_run_id": alert.scenario_run_id,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "status": alert.status,
        "title": alert.title,
        "why": alert.why,
        "reason": alert.why,
        "explanation": alert.why,
        "investigation": alert.investigation,
        "investigation_guidance": alert.investigation,
        "guidance": [alert.investigation],
        "false_positives": alert.false_positives,
        "attack_tags": alert.attack_tags,
        "techniques": alert.attack_tags,
        "attack_techniques": alert.attack_tags,
        "group_key": alert.group_key,
        "first_event_time": _aware(alert.first_event_time).isoformat(),
        "last_event_time": _aware(alert.last_event_time).isoformat(),
        "created_at": _aware(alert.created_at).isoformat(),
    }
    if include_evidence:
        rows = session.execute(
            select(AlertEvidence, NormalizedEvent)
            .join(NormalizedEvent, AlertEvidence.event_id == NormalizedEvent.id)
            .where(AlertEvidence.alert_id == alert.id)
            .order_by(AlertEvidence.position)
        ).all()
        result["evidence"] = [
            {"reason": evidence.reason, "event": serialize_event(event)} for evidence, event in rows
        ]
    return result


def build_timeline(
    session: Session,
    *,
    limit: int,
    host_id: str | None = None,
    rule_id: str | None = None,
    technique: str | None = None,
    severity: str | None = None,
    scenario_run_id: str | None = None,
) -> dict[str, Any]:
    postgres = session.get_bind().dialect.name == "postgresql"
    normalized_technique = technique.upper() if technique else None
    event_query = select(NormalizedEvent).order_by(NormalizedEvent.event_time.desc()).limit(limit)
    if host_id:
        event_query = event_query.where(NormalizedEvent.host_id == host_id)
    if scenario_run_id:
        event_query = event_query.where(NormalizedEvent.scenario_run_id == scenario_run_id)
    technique_evidence_ids: set[str] = set()
    if normalized_technique and postgres:
        evidence_subquery = (
            select(AlertEvidence.event_id)
            .join(Alert, AlertEvidence.alert_id == Alert.id)
            .where(cast(Alert.attack_tags, JSONB).contains([normalized_technique]))
        )
        event_query = event_query.where(
            or_(
                cast(NormalizedEvent.attack_tags, JSONB).contains([normalized_technique]),
                NormalizedEvent.id.in_(evidence_subquery),
            )
        )
    elif normalized_technique:
        # SQLite is a local demo/test fallback without JSONB operators. These scans
        # stay bounded by the requested timeline limit; PostgreSQL uses GIN above.
        tagged_alert_ids = [
            alert_id
            for alert_id, tags in session.execute(
                select(Alert.id, Alert.attack_tags).order_by(Alert.created_at.desc()).limit(limit)
            )
            if normalized_technique in tags
        ]
        if tagged_alert_ids:
            technique_evidence_ids = set(
                session.scalars(
                    select(AlertEvidence.event_id)
                    .where(AlertEvidence.alert_id.in_(tagged_alert_ids))
                    .limit(limit * 20)
                ).all()
            )
    events = list(reversed(session.scalars(event_query).all()))
    if normalized_technique and not postgres:
        events = [
            event
            for event in events
            if normalized_technique in event.attack_tags or event.id in technique_evidence_ids
        ]
    event_ids = {event.id for event in events}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    by_guid: dict[str, str] = {}
    scenario_nodes: set[str] = set()
    for event in events:
        node_type = "event"
        if event.event_type.startswith("process"):
            node_type = "process"
        elif event.event_type in {"network_connection", "dns_query"}:
            node_type = "network"
        elif event.event_type.startswith("file_"):
            node_type = "file"
        elif event.event_type.startswith("registry_"):
            node_type = "registry"
        hostname = event.data_json.get("host", {}).get("hostname")
        label = (
            event.data_json.get("process", {}).get("name")
            or event.data_json.get("file", {}).get("path")
            or event.event_type
        )
        nodes.append(
            {
                "id": f"event:{event.id}",
                "type": node_type,
                "label": label,
                "timestamp": _aware(event.event_time).isoformat(),
                "cluster": f"{event.host_id}:{event.event_type}",
                "host": hostname,
                "event_id": event.id,
                "source_event_id": event.source_event_id,
                "event_type": event.event_type,
                "scenario_run_id": event.scenario_run_id,
                "techniques": event.attack_tags,
                "severity": "informational",
                "evidence_ids": [],
                "details": event.data_json,
                "event": serialize_event(event),
            }
        )
        if event.process_guid:
            by_guid[event.process_guid] = event.id
        if event.scenario_run_id:
            scenario_node = f"scenario:{event.scenario_run_id}"
            if scenario_node not in scenario_nodes:
                scenario_nodes.add(scenario_node)
                nodes.append(
                    {
                        "id": scenario_node,
                        "type": "scenario",
                        "label": "Scenario run",
                        "cluster": event.scenario_run_id,
                    }
                )
            edges.append(
                {
                    "id": f"scenario-edge:{event.id}",
                    "source": scenario_node,
                    "target": f"event:{event.id}",
                    "type": "scenario",
                }
            )
    for event in events:
        if event.parent_process_guid and event.parent_process_guid in by_guid:
            edges.append(
                {
                    "id": f"process-edge:{event.id}",
                    "source": f"event:{by_guid[event.parent_process_guid]}",
                    "target": f"event:{event.id}",
                    "type": "process",
                }
            )
    alert_query = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if rule_id:
        alert_query = alert_query.where(Alert.rule_id == rule_id)
    if severity:
        alert_query = alert_query.where(Alert.severity == severity)
    if scenario_run_id:
        alert_query = alert_query.where(Alert.scenario_run_id == scenario_run_id)
    if normalized_technique and postgres:
        alert_query = alert_query.where(
            cast(Alert.attack_tags, JSONB).contains([normalized_technique])
        )
    alerts = session.scalars(alert_query).all()
    if normalized_technique and not postgres:
        alerts = [alert for alert in alerts if normalized_technique in alert.attack_tags]
    for alert in alerts:
        evidence_rows = session.scalars(
            select(AlertEvidence)
            .where(AlertEvidence.alert_id == alert.id)
            .order_by(AlertEvidence.position)
        ).all()
        visible = [row.event_id for row in evidence_rows if row.event_id in event_ids]
        if not visible:
            continue
        alert_record = serialize_alert(session, alert, include_evidence=False)
        nodes.append(
            {
                "id": f"alert:{alert.id}",
                "type": "alert",
                "label": alert.title,
                "timestamp": _aware(alert.created_at).isoformat(),
                "cluster": f"alert:{alert.rule_id}",
                "host": alert_record["host"]["hostname"] if alert_record["host"] else None,
                "severity": alert.severity,
                "techniques": alert.attack_tags,
                "rule_id": alert.rule_id,
                "scenario_run_id": alert.scenario_run_id,
                "evidence_ids": visible,
                "details": alert_record,
                "alert": alert_record,
            }
        )
        for event_id in visible:
            edges.append(
                {
                    "id": f"alert-edge:{alert.id}:{event_id}",
                    "source": f"event:{event_id}",
                    "target": f"alert:{alert.id}",
                    "type": "alert",
                }
            )
        rule = session.get(DetectionRule, alert.rule_id)
        correlation = (
            rule.definition_json.get("sentinelforge", {}).get("correlation") if rule else None
        )
        if correlation:
            for position, (source_id, target_id) in enumerate(
                zip(visible, visible[1:], strict=False)
            ):
                edges.append(
                    {
                        "id": f"correlation-edge:{alert.id}:{position}",
                        "source": f"event:{source_id}",
                        "target": f"event:{target_id}",
                        "type": "correlation",
                        "rule_id": alert.rule_id,
                    }
                )
    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "event_count": len(events),
            "node_count": len(nodes),
            "truncated": len(events) >= limit,
        },
    }


def purge_old_events(session: Session, retention_days: int, dry_run: bool) -> dict[str, Any]:
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    event_count = session.scalar(
        select(func.count()).select_from(NormalizedEvent).where(NormalizedEvent.event_time < cutoff)
    )
    raw_count = session.scalar(
        select(func.count()).select_from(RawEvent).where(RawEvent.event_time < cutoff)
    )
    if not dry_run:
        # Evidence cascades with normalized events. Evidence-free alerts remain for audit.
        session.execute(delete(NormalizedEvent).where(NormalizedEvent.event_time < cutoff))
        session.execute(delete(RawEvent).where(RawEvent.event_time < cutoff))
    return {
        "cutoff": cutoff.isoformat(),
        "normalized_events": event_count or 0,
        "raw_events": raw_count or 0,
        "dry_run": dry_run,
    }
