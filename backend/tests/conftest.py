from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sentinelforge.config import Settings
from sentinelforge.main import create_app


@pytest.fixture()
def client(tmp_path: Path) -> Iterator[TestClient]:
    rules_path = Path(__file__).resolve().parents[2] / "detections" / "rules"
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        rules_path=rules_path,
        enrollment_key="test-enrollment-key",
        admin_key="test-admin-key",
        token_pepper="test-token-pepper",
        lab_mode=False,
        auto_create_schema=True,
        max_request_bytes=2_097_152,
        max_batch_events=500,
        cors_origins=("http://localhost:3000",),
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture()
def enrolled(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/sensors/enroll",
        headers={"X-Enrollment-Key": "test-enrollment-key"},
        json={
            "name": "pytest sensor",
            "host_identifier": "pytest-host-id",
            "hostname": "PYTEST-HOST",
            "os_name": "Windows",
            "os_version": "11",
        },
    )
    assert response.status_code == 201
    return response.json()


def event(
    event_id: str = "evt-1",
    *,
    event_type: str = "process_start",
    command_line: str = "cmd.exe /c echo safe",
    name: str = "cmd.exe",
    executable: str = "C:\\Windows\\System32\\cmd.exe",
    when: datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "event_id": event_id,
        "event_time": (when or datetime(2026, 7, 27, 12, tzinfo=UTC)).isoformat(),
        "event_type": event_type,
        "host": {"hostname": "PYTEST-HOST", "os_name": "Windows"},
        "source": {"provider": "pytest", "event_code": "1"},
        "user": {"name": "analyst", "domain": "LAB"},
        "process": {
            "pid": 1234,
            "guid": f"guid-{event_id}",
            "name": name,
            "executable": executable,
            "command_line": command_line,
        },
        "attack_tags": [],
        "metadata": {},
    }
    value.update(extra)
    return value


@pytest.fixture()
def event_factory():
    return event


def ingest(
    client: TestClient,
    enrolled: dict[str, str],
    events: list[dict[str, Any]],
    batch_id: str = "batch-1",
):
    try:
        normalized_batch_id = str(uuid.UUID(batch_id))
    except ValueError:
        normalized_batch_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinelforge-test:{batch_id}"))
    return client.post(
        "/api/v1/events/batch",
        headers={"Authorization": f"Bearer {enrolled['ingestion_token']}"},
        json={
            "sensor_id": enrolled["sensor_id"],
            "schema_version": "1.0",
            "batch_id": normalized_batch_id,
            "events": events,
        },
    )


@pytest.fixture()
def ingest_events():
    return ingest
