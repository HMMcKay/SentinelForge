from __future__ import annotations

ADMIN = {"X-Admin-Key": "test-admin-key"}


def test_deterministic_demo_seed_is_idempotent(client) -> None:
    first = client.post("/api/v1/demo/seed", headers=ADMIN, json={"seed": 1337})
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["accepted"] == 19
    assert body["event_count"] == 19
    assert body["alerts_created"] >= 7
    second = client.post("/api/v1/demo/seed", headers=ADMIN, json={"seed": 1337})
    assert second.status_code == 200
    assert second.json()["idempotent_replay"] is True
    assert client.get("/api/v1/events").json()["total"] == 19


def test_timeline_coverage_and_export(client) -> None:
    seeded = client.post("/api/v1/demo/seed", headers=ADMIN, json={"seed": 42}).json()
    timeline = client.get(
        "/api/v1/timeline", params={"scenario_run_id": seeded["scenario_run_id"]}
    ).json()
    assert timeline["meta"]["event_count"] == 19
    assert any(node["type"] == "alert" for node in timeline["nodes"])
    assert any(edge["type"] == "process" for edge in timeline["edges"])
    assert any(edge["type"] == "correlation" for edge in timeline["edges"])
    assert any(edge["type"] == "scenario" for edge in timeline["edges"])
    assert any(edge["type"] == "alert" for edge in timeline["edges"])
    event_nodes = [
        node
        for node in timeline["nodes"]
        if node["type"] in {"event", "process", "network", "file", "registry"}
    ]
    alert_node = next(node for node in timeline["nodes"] if node["type"] == "alert")
    visible_event_ids = {node["event_id"] for node in event_nodes}
    assert alert_node["evidence_ids"]
    assert set(alert_node["evidence_ids"]) <= visible_event_ids
    assert alert_node["rule_id"]
    assert alert_node["severity"] in {"low", "medium", "high", "critical"}
    assert alert_node["techniques"]
    assert alert_node["scenario_run_id"] == seeded["scenario_run_id"]
    assert alert_node["host"]
    assert all(node["host"] and node["event_type"] and node["details"] for node in event_nodes)
    first_alert = client.get("/api/v1/alerts").json()["items"][0]
    assert first_alert["host"]["hostname"]

    coverage = client.get("/api/v1/attack/coverage").json()
    assert coverage["summary"]["techniques_covered"] >= 7
    technique = next(item for item in coverage["items"] if item["technique_id"] == "T1059.001")
    assert technique["rule_count"] >= 1
    assert technique["alert_count"] >= 1

    exported = client.get(
        "/api/v1/investigations/export",
        headers=ADMIN,
        params={"scenario_run_id": seeded["scenario_run_id"]},
    )
    assert exported.status_code == 200
    assert len(exported.json()["events"]) == 19
    assert exported.json()["alerts"]


def test_dashboard_contract_exposes_direct_normalized_fields(client) -> None:
    client.post("/api/v1/demo/seed", headers=ADMIN, json={"seed": 11})
    event = client.get("/api/v1/events").json()["items"][0]
    assert event["host"]["hostname"]
    assert event["ingested_at"]
    assert event["category"]
    assert event["action"] == event["event_type"]
    assert "techniques" in event
    alert = client.get("/api/v1/alerts").json()["items"][0]
    assert alert["host"]["name"]
    assert alert["reason"] == alert["why"]
    assert alert["guidance"]
    assert alert["techniques"] == alert["attack_tags"]
    rule = client.get("/api/v1/rules").json()["items"][0]
    assert rule["source"] == "sigma"
    assert rule["techniques"] == rule["attack_tags"]
    assert rule["log_sources"]
    sensor = client.get("/api/v1/sensors").json()["items"][0]
    assert sensor["hostname"]


def test_scenario_lab_gate(client) -> None:
    parameterized = client.post(
        "/api/v1/scenarios/encoded-powershell/runs",
        headers=ADMIN,
        json={"dry_run": True, "parameters": {"command": "not-allowed"}},
    )
    assert parameterized.status_code == 422
    live = client.post(
        "/api/v1/scenarios/encoded-powershell/runs",
        headers=ADMIN,
        json={"dry_run": False, "parameters": {}},
    )
    assert live.status_code == 403
    dry = client.post(
        "/api/v1/scenarios/encoded-powershell/runs",
        headers=ADMIN,
        json={"dry_run": True, "parameters": {}},
    )
    assert dry.status_code == 202
    assert dry.json()["status"] == "validated"
    assert dry.json()["cleanup_verified"] is True


def test_purge_defaults_to_preview(client) -> None:
    client.post("/api/v1/demo/seed", headers=ADMIN, json={"seed": 7})
    preview = client.post(
        "/api/v1/maintenance/purge",
        headers=ADMIN,
        json={"retention_days": 1, "dry_run": True},
    ).json()
    assert preview["normalized_events"] == 19
    assert client.get("/api/v1/events").json()["total"] == 19
