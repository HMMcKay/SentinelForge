from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EVENT_TYPES = Literal[
    "process_start",
    "process_end",
    "network_connection",
    "dns_query",
    "file_create",
    "file_modify",
    "file_delete",
    "registry_set",
    "registry_delete",
    "scheduled_task",
    "powershell",
    "security_control",
    "authentication",
]

ATTACK_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
UUID_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class HostRef(StrictModel):
    hostname: str = Field(min_length=1, max_length=255)
    host_id: str | None = Field(default=None, max_length=255)
    os_name: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)


class UserRef(StrictModel):
    name: str | None = Field(default=None, max_length=255)
    domain: str | None = Field(default=None, max_length=255)
    sid: str | None = Field(default=None, max_length=184)


class ProcessRef(StrictModel):
    pid: int | None = Field(default=None, ge=0, le=4_294_967_295)
    guid: str | None = Field(default=None, max_length=128)
    name: str | None = Field(default=None, max_length=255)
    executable: str | None = Field(default=None, max_length=32768)
    command_line: str | None = Field(default=None, max_length=32768)
    parent_pid: int | None = Field(default=None, ge=0, le=4_294_967_295)
    parent_guid: str | None = Field(default=None, max_length=128)
    parent_name: str | None = Field(default=None, max_length=255)
    parent_executable: str | None = Field(default=None, max_length=32768)
    integrity_level: str | None = Field(default=None, max_length=64)
    sha256: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{64}$")


class NetworkRef(StrictModel):
    source_ip: str | None = Field(default=None, max_length=64)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_ip: str | None = Field(default=None, max_length=64)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    dns_question: str | None = Field(default=None, max_length=253)


class FileRef(StrictModel):
    path: str = Field(min_length=1, max_length=32768)
    operation: Literal["create", "modify", "delete", "rename"]
    sha256: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{64}$")
    size: int | None = Field(default=None, ge=0)


class RegistryRef(StrictModel):
    key_path: str = Field(min_length=1, max_length=32768)
    value_name: str | None = Field(default=None, max_length=16384)
    value_data: str | None = Field(default=None, max_length=65536)
    operation: Literal["set", "delete", "create_key", "delete_key"]


class SourceRef(StrictModel):
    provider: str = Field(min_length=1, max_length=255)
    channel: str | None = Field(default=None, max_length=255)
    event_code: str | None = Field(default=None, max_length=32)
    record_id: str | None = Field(default=None, max_length=64)


class NormalizedEventIn(StrictModel):
    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:{}-]+$")
    event_time: datetime
    event_type: EVENT_TYPES
    host: HostRef
    source: SourceRef
    raw_event_ref: str | None = Field(default=None, max_length=256)
    user: UserRef | None = None
    process: ProcessRef | None = None
    network: NetworkRef | None = None
    file: FileRef | None = None
    registry: RegistryRef | None = None
    scenario_run_id: str | None = Field(default=None, max_length=36, pattern=UUID_PATTERN)
    attack_tags: list[str] = Field(default_factory=list, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_time")
    @classmethod
    def event_time_requires_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event_time must include an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("attack_tags")
    @classmethod
    def validate_attack_tags(cls, value: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(item.upper() for item in value))
        invalid = [item for item in normalized if not ATTACK_PATTERN.fullmatch(item)]
        if invalid:
            raise ValueError(f"invalid ATT&CK technique IDs: {', '.join(invalid)}")
        return normalized

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 64:
            raise ValueError("metadata may contain at most 64 top-level keys")
        return value

    @model_validator(mode="after")
    def require_type_payload(self) -> NormalizedEventIn:
        requirements = {
            "network_connection": self.network,
            "dns_query": self.network,
            "file_create": self.file,
            "file_modify": self.file,
            "file_delete": self.file,
            "registry_set": self.registry,
            "registry_delete": self.registry,
        }
        if self.event_type in requirements and requirements[self.event_type] is None:
            raise ValueError(f"{self.event_type} requires its corresponding typed object")
        if (
            self.event_type in {"process_start", "process_end", "powershell"}
            and self.process is None
        ):
            raise ValueError(f"{self.event_type} requires process")
        return self


class EventBatchIn(StrictModel):
    sensor_id: str = Field(min_length=36, max_length=36, pattern=UUID_PATTERN)
    schema_version: Literal["1.0"] = "1.0"
    batch_id: str = Field(min_length=36, max_length=36, pattern=UUID_PATTERN)
    events: list[NormalizedEventIn] = Field(min_length=1, max_length=500)


class SensorEnrollIn(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    host_identifier: str = Field(min_length=1, max_length=255)
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(default="Windows", min_length=1, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SensorHeartbeatIn(StrictModel):
    status: Literal["healthy", "degraded"]
    agent_version: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9.+_-]+$")
    service_mode: bool
    spool_event_count: int = Field(ge=0, le=10_000_000)
    spool_bytes: int = Field(ge=0, le=1_099_511_627_776)
    last_event_time: datetime | None = None
    error_codes: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("last_event_time")
    @classmethod
    def health_times_require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("health timestamps must include an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("error_codes")
    @classmethod
    def validate_error_codes(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", item) for item in value):
            raise ValueError("error_codes must be redacted identifiers of at most 64 characters")
        return list(dict.fromkeys(value))


class ScenarioRunIn(StrictModel):
    sensor_id: str | None = Field(default=None, max_length=36, pattern=UUID_PATTERN)
    dry_run: bool = True
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("parameters")
    @classmethod
    def limit_parameters(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value:
            raise ValueError("scenario parameters are not supported in schema version 1.0")
        return value


class ScenarioRunStatusIn(StrictModel):
    status: Literal["running", "completed", "failed"]
    cleanup_verified: bool | None = None
    error_summary: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def completed_requires_cleanup(self) -> ScenarioRunStatusIn:
        if self.status == "completed" and self.cleanup_verified is not True:
            raise ValueError("completed runs require cleanup_verified=true")
        if self.status == "completed" and self.error_summary:
            raise ValueError("completed runs may not include error_summary")
        return self


class DemoSeedIn(StrictModel):
    seed: int = Field(default=1337, ge=0, le=2_147_483_647)
    reset_demo: bool = False


class PurgeIn(StrictModel):
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    dry_run: bool = True
