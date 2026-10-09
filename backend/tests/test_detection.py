from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinelforge.detection import (
    RuleValidationError,
    load_rules,
    match_rule,
    validate_rule,
)


def _rule() -> dict:
    return {
        "title": "Test",
        "id": "SF-TEST-RULE",
        "description": "Test rule",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"process.command_line|contains": "-encodedcommand"},
            "condition": "selection",
        },
        "level": "high",
    }


def test_validator_rejects_unsupported_modifier_and_timeframe() -> None:
    rule = _rule()
    rule["detection"]["selection"] = {"process.command_line|base64": "value"}
    with pytest.raises(RuleValidationError, match="unsupported modifier"):
        validate_rule(rule)
    rule = _rule()
    rule["detection"]["timeframe"] = "5m"
    with pytest.raises(RuleValidationError, match="timeframe"):
        validate_rule(rule)
    rule = _rule()
    rule["detection"]["selection"] = {"process.command_line|contains|startswith": "powershell"}
    with pytest.raises(RuleValidationError, match="incompatible modifiers"):
        validate_rule(rule)


def test_condition_and_case_insensitive_contains_evaluation() -> None:
    rule = validate_rule(_rule())
    assert match_rule({"process": {"command_line": "PowerShell.EXE -EncodedCommand AAA"}}, rule)
    assert not match_rule({"process": {"command_line": "powershell Write-Output safe"}}, rule)


def test_repository_rules_validate() -> None:
    rules_path = Path(__file__).resolve().parents[2] / "detections" / "rules"
    rules, errors = load_rules(rules_path)
    assert errors == []
    assert len(rules) >= 7
    assert len({rule.id for rule in rules}) == len(rules)


def test_encoded_powershell_alert_contains_explainable_evidence(
    client, enrolled, event_factory, ingest_events
) -> None:
    event = event_factory(
        "encoded",
        event_type="process_start",
        name="powershell.exe",
        executable="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA",
    )
    response = ingest_events(client, enrolled, [event], "encoded")
    assert response.status_code == 200
    assert response.json()["alerts_created"] == 1
    alert = client.get("/api/v1/alerts").json()["items"][0]
    detail = client.get(f"/api/v1/alerts/{alert['id']}").json()
    assert detail["rule_id"] == "SF-POWERSHELL-ENCODED"
    assert detail["why"]
    assert detail["investigation"]
    assert detail["evidence"][0]["event"]["source_event_id"] == "encoded"
    assert "T1059.001" in detail["attack_tags"]


def test_encoded_pwsh_seven_is_detected(client, enrolled, event_factory, ingest_events) -> None:
    event = event_factory(
        "encoded-pwsh",
        name="pwsh.exe",
        executable="C:\\Program Files\\PowerShell\\7\\pwsh.exe",
        command_line="pwsh.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA",
    )
    response = ingest_events(client, enrolled, [event], "encoded-pwsh")
    assert response.status_code == 200
    assert response.json()["alerts_created"] == 1
    assert client.get("/api/v1/alerts").json()["items"][0]["rule_id"] == ("SF-POWERSHELL-ENCODED")


def test_threshold_and_sequence_correlations(
    client, enrolled, event_factory, ingest_events
) -> None:
    base = datetime(2026, 7, 27, 13, tzinfo=UTC)
    shell = event_factory("shell", when=base)
    powershell = event_factory(
        "powershell",
        event_type="process_start",
        name="powershell.exe",
        executable="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe Write-Output safe",
        when=base + timedelta(seconds=1),
    )
    response = ingest_events(client, enrolled, [shell, powershell], "sequence")
    assert response.status_code == 200
    assert response.json()["alerts_created"] == 1

    files = []
    for index in range(5):
        item = event_factory(
            f"file-{index}",
            event_type="file_modify",
            name="bulk.exe",
            executable="C:\\SentinelForgeLab\\bulk.exe",
            when=base + timedelta(minutes=1, seconds=index),
        )
        item["file"] = {
            "path": f"C:\\SentinelForgeLab\\synthetic\\{index}.txt",
            "operation": "modify",
        }
        item["process"]["guid"] = "guid-bulk-process"
        files.append(item)
    response = ingest_events(client, enrolled, files, "threshold")
    assert response.status_code == 200
    assert response.json()["alerts_created"] == 1
    rule_ids = {item["rule_id"] for item in client.get("/api/v1/alerts").json()["items"]}
    assert "SF-CMD-POWERSHELL-SEQUENCE" in rule_ids
    assert "SF-FILE-MODIFICATION-BURST" in rule_ids


def test_file_create_events_feed_the_write_burst_rule(
    client, enrolled, event_factory, ingest_events
) -> None:
    base = datetime(2026, 7, 27, 14, tzinfo=UTC)
    files = []
    for index in range(5):
        item = event_factory(
            f"create-{index}",
            event_type="file_create",
            name="emulator.exe",
            executable="C:\\SentinelForgeLab\\emulator.exe",
            when=base + timedelta(seconds=index),
        )
        item["process"]["guid"] = "guid-file-create-burst"
        item["file"] = {
            "path": f"C:\\SentinelForgeLab\\synthetic\\create-{index}.txt",
            "operation": "create",
        }
        files.append(item)
    response = ingest_events(client, enrolled, files, "file-create-burst")
    assert response.status_code == 200
    assert response.json()["alerts_created"] == 1


def test_scheduled_task_creation_has_a_near_miss(
    client, enrolled, event_factory, ingest_events
) -> None:
    create = event_factory(
        "task-create",
        name="schtasks.exe",
        executable="C:\\Windows\\System32\\schtasks.exe",
        command_line="schtasks.exe /Create /TN SentinelForge\\Test /SC ONCE /ST 23:59",
    )
    query = event_factory(
        "task-query",
        name="schtasks.exe",
        executable="C:\\Windows\\System32\\schtasks.exe",
        command_line="schtasks.exe /Query /TN SentinelForge\\Test",
    )
    response = ingest_events(client, enrolled, [create, query], "scheduled-task")
    assert response.status_code == 200
    matching = [
        alert
        for alert in client.get("/api/v1/alerts").json()["items"]
        if alert["rule_id"] == "SF-SCHEDULED-TASK-CREATE"
    ]
    assert len(matching) == 1
    detail = client.get(f"/api/v1/alerts/{matching[0]['id']}").json()
    assert [item["event"]["source_event_id"] for item in detail["evidence"]] == ["task-create"]
