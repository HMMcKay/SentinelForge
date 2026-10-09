from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from sentinelforge.models import ScenarioRun


def test_health_and_security_headers(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["rules_loaded"] >= 7
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"]


def test_enrollment_requires_secret_and_token_is_returned_once(client: TestClient) -> None:
    body = {
        "name": "sensor",
        "host_identifier": "host-unique",
        "hostname": "HOST",
        "os_name": "Windows",
    }
    assert client.post("/api/v1/sensors/enroll", json=body).status_code == 401
    response = client.post(
        "/api/v1/sensors/enroll",
        headers={"X-Enrollment-Key": "test-enrollment-key"},
        json=body,
    )
    assert response.status_code == 201
    assert response.json()["ingestion_token"]
    listed = client.get("/api/v1/sensors").json()["items"]
    assert len(listed) == 1
    assert "ingestion_token" not in listed[0]
    assert "token_hash" not in listed[0]
    duplicate = client.post(
        "/api/v1/sensors/enroll",
        headers={"X-Enrollment-Key": "test-enrollment-key"},
        json=body,
    )
    assert duplicate.status_code == 409


def test_ingestion_auth_validation_and_idempotency(
    client: TestClient, enrolled, event_factory, ingest_events
) -> None:
    payload = {
        "sensor_id": enrolled["sensor_id"],
        "schema_version": "1.0",
        "batch_id": str(uuid.uuid4()),
        "events": [event_factory("auth-1")],
    }
    assert client.post("/api/v1/events/batch", json=payload).status_code == 401
    response = ingest_events(client, enrolled, payload["events"], "batch-auth")
    assert response.status_code == 200
    body = response.json()
    assert uuid.UUID(body["batch_id"])
    assert body["accepted"] == 1
    assert body["duplicates"] == 0
    assert body["alerts_created"] == 0
    assert body["idempotent_replay"] is False
    replay = ingest_events(client, enrolled, payload["events"], "batch-auth")
    assert replay.status_code == 200
    assert replay.json()["idempotent_replay"] is True
    assert client.get("/api/v1/events").json()["total"] == 1


def test_schema_is_strict_and_requires_timezone(
    client: TestClient, enrolled, event_factory, ingest_events
) -> None:
    unexpected = event_factory("bad-extra")
    unexpected["unexpected"] = True
    response = ingest_events(client, enrolled, [unexpected], "bad-extra")
    assert response.status_code == 422
    naive = event_factory("bad-time")
    naive["event_time"] = "2026-07-27T12:00:00"
    response = ingest_events(client, enrolled, [naive], "bad-time")
    assert response.status_code == 422


def test_sensor_id_must_match_bearer_token(client: TestClient, enrolled, event_factory) -> None:
    response = client.post(
        "/api/v1/events/batch",
        headers={"Authorization": f"Bearer {enrolled['ingestion_token']}"},
        json={
            "sensor_id": "00000000-0000-4000-8000-000000000000",
            "schema_version": "1.0",
            "batch_id": str(uuid.uuid4()),
            "events": [event_factory("wrong-sensor")],
        },
    )
    assert response.status_code == 403


def test_admin_operations_require_key(client: TestClient) -> None:
    assert client.post("/api/v1/demo/seed", json={"seed": 1}).status_code == 401
    response = client.post(
        "/api/v1/maintenance/purge",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"retention_days": 30, "dry_run": True},
    )
    assert response.status_code == 200
    assert response.json()["dry_run"] is True


def test_actual_chunked_body_size_is_enforced(client: TestClient) -> None:
    def oversized_body():
        yield b"{" + b"a" * 1_100_000
        yield b"b" * 1_100_000 + b"}"

    response = client.post(
        "/api/v1/demo/seed",
        headers={
            "X-Admin-Key": "test-admin-key",
            "Content-Type": "application/json",
            "Transfer-Encoding": "chunked",
        },
        content=oversized_body(),
    )
    assert response.status_code == 413


def test_live_websocket_announces_committed_ingestion(
    client: TestClient, enrolled, event_factory, ingest_events
) -> None:
    with client.websocket_connect("/api/v1/live") as websocket:
        assert websocket.receive_json() == {"type": "connected", "schema_version": "1.0"}
        response = ingest_events(client, enrolled, [event_factory("live-1")], "live-batch")
        assert response.status_code == 200
        message = websocket.receive_json()
        assert message["type"] == "ingest"
        assert message["sensor_id"] == enrolled["sensor_id"]
        assert message["accepted"] == 1


def test_sensor_runner_protocol_is_scoped_and_enforces_transitions(
    client: TestClient, enrolled
) -> None:
    second_response = client.post(
        "/api/v1/sensors/enroll",
        headers={"X-Enrollment-Key": "test-enrollment-key"},
        json={
            "name": "second sensor",
            "host_identifier": "pytest-host-id-2",
            "hostname": "PYTEST-HOST-2",
            "os_name": "Windows",
        },
    )
    second = second_response.json()
    with client.app.state.database.session_factory() as session:
        run = ScenarioRun(
            scenario_id="encoded-powershell",
            sensor_id=enrolled["sensor_id"],
            status="requested",
            dry_run=False,
            parameters_json={"must_not_be_dispatched": "arbitrary command"},
        )
        session.add(run)
        session.commit()
        run_id = run.id
    first_headers = {"Authorization": f"Bearer {enrolled['ingestion_token']}"}
    second_headers = {"Authorization": f"Bearer {second['ingestion_token']}"}
    pending = client.get("/api/v1/scenario-runs/pending", headers=first_headers)
    assert pending.status_code == 200
    assert pending.json() == {
        "run": {
            "run_id": run_id,
            "scenario_id": "encoded-powershell",
            "sensor_id": enrolled["sensor_id"],
            "dry_run": False,
        }
    }
    assert client.get("/api/v1/scenario-runs/pending", headers=second_headers).json() == {
        "run": None
    }
    assert (
        client.post(
            f"/api/v1/scenario-runs/{run_id}/status",
            headers=second_headers,
            json={"status": "running"},
        ).status_code
        == 404
    )
    running = client.post(
        f"/api/v1/scenario-runs/{run_id}/status",
        headers=first_headers,
        json={"status": "running"},
    )
    assert running.status_code == 200
    assert running.json()["status"] == "running"
    duplicate_claim = client.post(
        f"/api/v1/scenario-runs/{run_id}/status",
        headers=first_headers,
        json={"status": "running"},
    )
    assert duplicate_claim.status_code == 409
    assert (
        client.post(
            f"/api/v1/scenario-runs/{run_id}/status",
            headers=first_headers,
            json={"status": "completed", "cleanup_verified": False},
        ).status_code
        == 422
    )
    completed = client.post(
        f"/api/v1/scenario-runs/{run_id}/status",
        headers=first_headers,
        json={"status": "completed", "cleanup_verified": True},
    )
    assert completed.status_code == 200
    assert completed.json()["cleanup_verified"] is True
    assert (
        client.post(
            f"/api/v1/scenario-runs/{run_id}/status",
            headers=first_headers,
            json={"status": "failed", "cleanup_verified": True},
        ).status_code
        == 409
    )


def test_sensor_heartbeat_is_strict_and_owner_scoped(client: TestClient, enrolled) -> None:
    headers = {"Authorization": f"Bearer {enrolled['ingestion_token']}"}
    body = {
        "status": "healthy",
        "agent_version": "0.1.0",
        "service_mode": True,
        "spool_event_count": 2,
        "spool_bytes": 4096,
        "last_event_time": "2026-07-27T11:59:59Z",
        "error_codes": ["upload.rejected"],
    }
    response = client.post(
        f"/api/v1/sensors/{enrolled['sensor_id']}/heartbeat", headers=headers, json=body
    )
    assert response.status_code == 200
    health = client.get("/api/v1/sensors").json()["items"][0]["health"]
    assert health["status"] == "healthy"
    assert health["spool_event_count"] == 2
    assert health["error_codes"] == ["upload.rejected"]
    assert (
        client.post(
            "/api/v1/sensors/00000000-0000-0000-0000-000000000000/heartbeat",
            headers=headers,
            json=body,
        ).status_code
        == 404
    )
    invalid = {**body, "unbounded_extension": "rejected"}
    assert (
        client.post(
            f"/api/v1/sensors/{enrolled['sensor_id']}/heartbeat", headers=headers, json=invalid
        ).status_code
        == 422
    )
