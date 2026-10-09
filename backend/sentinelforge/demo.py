from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from .detection import DetectionEngine
from .models import ScenarioRun, Sensor
from .schemas import EventBatchIn
from .security import hash_token
from .services import ingest_batch

DEMO_NAMESPACE = uuid.UUID("86b158a3-1088-4452-b899-918b28286ebc")


def _uuid(name: str) -> str:
    return str(uuid.uuid5(DEMO_NAMESPACE, name))


def _event(
    seed: int,
    index: int,
    event_type: str,
    when: datetime,
    *,
    hostname: str = "SF-LAB-01",
    process: dict[str, Any] | None = None,
    network: dict[str, Any] | None = None,
    file: dict[str, Any] | None = None,
    registry: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    attack_tags: list[str] | None = None,
    scenario_run_id: str | None = None,
) -> dict[str, Any]:
    return {
        "event_id": f"demo-{seed}-{index:03d}",
        "event_time": when.isoformat(),
        "event_type": event_type,
        "host": {"hostname": hostname, "os_name": "Windows", "os_version": "11 Lab"},
        "source": {
            "provider": "SentinelForge.Demo",
            "channel": "Synthetic",
            "event_code": str(index),
            "record_id": str(index),
        },
        "user": {"name": "analyst", "domain": "LAB", "sid": "S-1-5-21-1000"},
        "process": process,
        "network": network,
        "file": file,
        "registry": registry,
        "scenario_run_id": scenario_run_id,
        "attack_tags": attack_tags or [],
        "metadata": {"demo": True, "seed": seed, **(metadata or {})},
    }


def _events(seed: int, run_id: str) -> list[dict[str, Any]]:
    base = datetime(2026, 1, 15, 18, 0, tzinfo=UTC) + timedelta(seconds=seed % 86400)
    parent_guid = _uuid(f"{seed}:parent")
    powershell_guid = _uuid(f"{seed}:powershell")
    events = [
        _event(
            seed,
            1,
            "process_start",
            base,
            process={
                "pid": 4100,
                "guid": parent_guid,
                "name": "cmd.exe",
                "executable": "C:\\Windows\\System32\\cmd.exe",
                "command_line": "cmd.exe /c echo SentinelForge demo",
            },
            scenario_run_id=run_id,
        ),
        _event(
            seed,
            2,
            "process_start",
            base + timedelta(seconds=2),
            process={
                "pid": 4104,
                "guid": powershell_guid,
                "parent_pid": 4100,
                "parent_guid": parent_guid,
                "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": (
                    "powershell.exe -NoProfile -EncodedCommand "
                    "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMAZQBuAHQAaQBuAGUAbABGAG8AcgBnAGUAJwA="
                ),
            },
            attack_tags=["T1059.001", "T1027.010"],
            scenario_run_id=run_id,
        ),
        # Near miss: PowerShell without the encoded-command switch.
        _event(
            seed,
            3,
            "process_start",
            base + timedelta(seconds=4),
            process={
                "pid": 4108,
                "guid": _uuid(f"{seed}:near-powershell"),
                "parent_pid": 4100,
                "parent_guid": parent_guid,
                "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -NoProfile Write-Output 'ordinary administration'",
            },
            scenario_run_id=run_id,
        ),
        _event(
            seed,
            4,
            "registry_set",
            base + timedelta(seconds=7),
            process={
                "pid": 4104,
                "guid": powershell_guid,
                "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "New-ItemProperty -Name SentinelForgeDemo",
            },
            registry={
                "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "SentinelForgeDemo",
                "value_data": "C:\\SentinelForgeLab\\marker.exe",
                "operation": "set",
            },
            attack_tags=["T1547.001"],
            scenario_run_id=run_id,
        ),
        _event(
            seed,
            5,
            "process_start",
            base + timedelta(seconds=10),
            process={
                "pid": 4200,
                "guid": _uuid(f"{seed}:schtasks"),
                "name": "schtasks.exe",
                "executable": "C:\\Windows\\System32\\schtasks.exe",
                "command_line": "schtasks /Create /TN SentinelForge\\Demo /SC ONCE /ST 23:59",
            },
            metadata={"task_name": "SentinelForge\\Demo", "action": "create"},
            attack_tags=["T1053.005"],
            scenario_run_id=run_id,
        ),
        _event(
            seed,
            6,
            "process_start",
            base + timedelta(seconds=12),
            process={
                "pid": 4300,
                "guid": _uuid(f"{seed}:user-writable"),
                "parent_pid": 4100,
                "parent_guid": parent_guid,
                "name": "sf-benign.exe",
                "executable": (
                    "C:\\Users\\analyst\\AppData\\Local\\Temp\\SentinelForge\\sf-benign.exe"
                ),
                "command_line": "sf-benign.exe --print-marker",
            },
            attack_tags=["T1204.002"],
            scenario_run_id=run_id,
        ),
        _event(
            seed,
            7,
            "dns_query",
            base + timedelta(seconds=15),
            process={
                "pid": 4300,
                "guid": _uuid(f"{seed}:user-writable"),
                "name": "sf-benign.exe",
                "executable": (
                    "C:\\Users\\analyst\\AppData\\Local\\Temp\\SentinelForge\\sf-benign.exe"
                ),
            },
            network={
                "destination_ip": "127.0.0.1",
                "protocol": "udp",
                "dns_question": "sf-test.invalid",
            },
            attack_tags=["T1071.004"],
            scenario_run_id=run_id,
        ),
    ]
    for offset in range(6):
        events.append(
            _event(
                seed,
                8 + offset,
                "file_modify",
                base + timedelta(seconds=20 + offset),
                process={
                    "pid": 4400,
                    "guid": _uuid(f"{seed}:ransomware-emulator"),
                    "name": "SentinelForge.Simulator.exe",
                    "executable": "C:\\SentinelForgeLab\\SentinelForge.Simulator.exe",
                },
                file={
                    "path": f"C:\\SentinelForgeLab\\synthetic\\document-{offset}.txt",
                    "operation": "modify",
                    "size": 128 + offset,
                },
                attack_tags=["T1486"],
                scenario_run_id=run_id,
            )
        )
    # Four matching file events on a second host exercise the threshold near-miss path.
    for offset in range(4):
        events.append(
            _event(
                seed,
                14 + offset,
                "file_modify",
                base + timedelta(seconds=30 + offset),
                hostname="SF-LAB-NEARMISS",
                process={
                    "pid": 4500,
                    "guid": _uuid(f"{seed}:near-ransomware"),
                    "name": "bulk-editor.exe",
                    "executable": "C:\\SentinelForgeLab\\bulk-editor.exe",
                },
                file={
                    "path": f"C:\\SentinelForgeLab\\synthetic\\near-{offset}.txt",
                    "operation": "modify",
                    "size": 64,
                },
                scenario_run_id=run_id,
            )
        )
    events.append(
        _event(
            seed,
            18,
            "security_control",
            base + timedelta(seconds=40),
            process={
                "pid": 4600,
                "guid": _uuid(f"{seed}:security-control"),
                "name": "SentinelForge.Simulator.exe",
                "executable": "C:\\SentinelForgeLab\\SentinelForge.Simulator.exe",
            },
            metadata={"control": "synthetic-antivirus", "action": "disable", "synthetic": True},
            attack_tags=["T1685"],
            scenario_run_id=run_id,
        )
    )
    # Near miss: task enumeration is normal visibility activity, not task creation.
    events.append(
        _event(
            seed,
            19,
            "process_start",
            base + timedelta(seconds=42),
            process={
                "pid": 4700,
                "guid": _uuid(f"{seed}:schtasks-query"),
                "name": "schtasks.exe",
                "executable": "C:\\Windows\\System32\\schtasks.exe",
                "command_line": "schtasks.exe /Query /TN SentinelForge\\Demo",
            },
            scenario_run_id=run_id,
        )
    )
    return events


def seed_demo(
    session: Session,
    engine: DetectionEngine,
    *,
    seed: int,
    token_pepper: str,
    reset_demo: bool = False,
) -> dict[str, Any]:
    sensor_id = _uuid(f"demo-sensor:{seed}")
    run_id = _uuid(f"demo-run:{seed}")
    if reset_demo:
        run = session.get(ScenarioRun, run_id)
        if run:
            session.delete(run)
            session.flush()
        sensor = session.get(Sensor, sensor_id)
        if sensor:
            session.delete(sensor)
            session.flush()
    sensor = session.get(Sensor, sensor_id)
    if sensor is None:
        sensor = Sensor(
            id=sensor_id,
            name=f"deterministic-demo-{seed}",
            host_identifier=f"sentinelforge-demo-{seed}",
            token_hash=hash_token(f"demo-token-{seed}", token_pepper),
            metadata_json={"demo": True, "seed": seed},
        )
        session.add(sensor)
        session.flush()
    run = session.get(ScenarioRun, run_id)
    if run is None:
        run = ScenarioRun(
            id=run_id,
            scenario_id="benign-process-chain",
            sensor_id=sensor.id,
            status="completed",
            dry_run=False,
            started_at=datetime(2026, 1, 15, tzinfo=UTC),
            completed_at=datetime(2026, 1, 15, 0, 1, tzinfo=UTC),
            cleanup_verified=True,
            parameters_json={"demo": True, "seed": seed},
        )
        session.add(run)
        session.flush()
    payload = EventBatchIn.model_validate(
        {
            "sensor_id": sensor.id,
            "schema_version": "1.0",
            "batch_id": _uuid(f"demo-batch:{seed}"),
            "events": _events(seed, run.id),
        }
    )
    result, alerts = ingest_batch(session, sensor, payload, engine)
    return {
        **result,
        "seed": seed,
        "sensor_id": sensor.id,
        "scenario_run_id": run.id,
        "event_count": len(payload.events),
        "alert_ids": [alert.id for alert in alerts],
    }
