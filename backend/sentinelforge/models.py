from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base

JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class Sensor(Base):
    __tablename__ = "sensors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    host_identifier: Mapped[str] = mapped_column(String(255), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, default=dict)

    hosts: Mapped[list[Host]] = relationship(back_populates="sensor", cascade="all, delete-orphan")


class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("sensor_id", "hostname", name="uq_host_sensor_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sensor_id: Mapped[str] = mapped_column(ForeignKey("sensors.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    os_name: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(128))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sensor: Mapped[Sensor] = relationship(back_populates="hosts")


class SensorHealth(Base):
    __tablename__ = "sensor_health"

    sensor_id: Mapped[str] = mapped_column(
        ForeignKey("sensors.id", ondelete="CASCADE"), primary_key=True
    )
    status: Mapped[str] = mapped_column(String(32), index=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    agent_version: Mapped[str] = mapped_column(String(32))
    service_mode: Mapped[bool] = mapped_column(Boolean)
    last_event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    spool_event_count: Mapped[int] = mapped_column(Integer, default=0)
    spool_bytes: Mapped[int] = mapped_column(Integer, default=0)
    error_codes: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, default=list)


class IngestBatch(Base):
    __tablename__ = "ingest_batches"
    __table_args__ = (UniqueConstraint("sensor_id", "batch_id", name="uq_batch_sensor_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sensor_id: Mapped[str] = mapped_column(ForeignKey("sensors.id", ondelete="CASCADE"), index=True)
    batch_id: Mapped[str] = mapped_column(String(128))
    schema_version: Mapped[str] = mapped_column(String(16))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    accepted_count: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)


class RawEvent(Base):
    __tablename__ = "raw_events"
    __table_args__ = (
        UniqueConstraint("sensor_id", "source_event_id", name="uq_raw_sensor_source_event"),
        Index("ix_raw_event_time_host", "event_time", "host_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sensor_id: Mapped[str] = mapped_column(ForeignKey("sensors.id", ondelete="CASCADE"), index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    source_event_id: Mapped[str] = mapped_column(String(128))
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingest_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    payload_sha256: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT)


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"
    __table_args__ = (
        UniqueConstraint("sensor_id", "source_event_id", name="uq_event_sensor_source_event"),
        Index("ix_event_time_host", "event_time", "host_id"),
        Index("ix_event_scenario_time", "scenario_run_id", "event_time"),
        Index("ix_event_process_guid", "process_guid"),
        Index("ix_event_attack_tags_gin", "attack_tags", postgresql_using="gin"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    schema_version: Mapped[str] = mapped_column(String(16), index=True)
    sensor_id: Mapped[str] = mapped_column(ForeignKey("sensors.id", ondelete="CASCADE"), index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    raw_event_id: Mapped[str] = mapped_column(ForeignKey("raw_events.id", ondelete="CASCADE"))
    source_event_id: Mapped[str] = mapped_column(String(128))
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingest_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    process_guid: Mapped[str | None] = mapped_column(String(128), index=True)
    parent_process_guid: Mapped[str | None] = mapped_column(String(128), index=True)
    scenario_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("scenario_runs.id", ondelete="SET NULL"), index=True
    )
    attack_tags: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, default=list)
    data_json: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT)


class ProcessActivity(Base):
    __tablename__ = "process_activity"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("normalized_events.id", ondelete="CASCADE"), unique=True
    )
    process_guid: Mapped[str | None] = mapped_column(String(128), index=True)
    parent_process_guid: Mapped[str | None] = mapped_column(String(128), index=True)
    pid: Mapped[int | None] = mapped_column(Integer)
    image: Mapped[str | None] = mapped_column(Text)
    command_line: Mapped[str | None] = mapped_column(Text)
    user_name: Mapped[str | None] = mapped_column(String(255))


class NetworkActivity(Base):
    __tablename__ = "network_activity"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("normalized_events.id", ondelete="CASCADE"), unique=True
    )
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(32))
    dns_question: Mapped[str | None] = mapped_column(String(253), index=True)


class FileActivity(Base):
    __tablename__ = "file_activity"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("normalized_events.id", ondelete="CASCADE"), unique=True
    )
    path: Mapped[str] = mapped_column(Text)
    operation: Mapped[str] = mapped_column(String(32), index=True)
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)


class RegistryActivity(Base):
    __tablename__ = "registry_activity"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("normalized_events.id", ondelete="CASCADE"), unique=True
    )
    key_path: Mapped[str] = mapped_column(Text)
    value_name: Mapped[str | None] = mapped_column(String(255))
    value_data: Mapped[str | None] = mapped_column(Text)
    operation: Mapped[str] = mapped_column(String(32), index=True)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (Index("ix_rule_attack_tags_gin", "attack_tags", postgresql_using="gin"),)

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(32), default="experimental")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source_path: Mapped[str] = mapped_column(Text)
    definition_json: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT)
    attack_tags: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuleVersion(Base):
    __tablename__ = "rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "definition_hash", name="uq_rule_version_hash"),
        Index("ix_rule_version_rule_version", "rule_id", "version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    definition_hash: Mapped[str] = mapped_column(String(64))
    definition_json: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alert_rule_created", "rule_id", "created_at"),
        Index("ix_alert_scenario_created", "scenario_run_id", "created_at"),
        Index("ix_alert_attack_tags_gin", "attack_tags", postgresql_using="gin"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"), index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    scenario_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("scenario_runs.id", ondelete="SET NULL"), index=True
    )
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    title: Mapped[str] = mapped_column(String(255))
    why: Mapped[str] = mapped_column(Text)
    investigation: Mapped[str] = mapped_column(Text)
    false_positives: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, default=list)
    attack_tags: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, default=list)
    group_key: Mapped[str | None] = mapped_column(String(512), index=True)
    dedup_key: Mapped[str] = mapped_column(String(64), index=True)
    first_event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    evidence: Mapped[list[AlertEvidence]] = relationship(
        back_populates="alert", cascade="all, delete-orphan", order_by="AlertEvidence.position"
    )


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"
    __table_args__ = (UniqueConstraint("alert_id", "event_id", name="uq_alert_event_evidence"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("normalized_events.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)

    alert: Mapped[Alert] = relationship(back_populates="evidence")


class CorrelationGroup(Base):
    __tablename__ = "correlation_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"), index=True)
    group_key: Mapped[str] = mapped_column(String(512), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer)
    closed: Mapped[bool] = mapped_column(Boolean, default=False)
    state_json: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, default=dict)


class Scenario(Base):
    __tablename__ = "scenarios"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    technique_ids: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, default=list)
    supported_platforms: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, default=list)
    safety_notes: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class ScenarioRun(Base):
    __tablename__ = "scenario_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scenario_id: Mapped[str] = mapped_column(ForeignKey("scenarios.id"), index=True)
    sensor_id: Mapped[str | None] = mapped_column(
        ForeignKey("sensors.id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="requested", index=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cleanup_verified: Mapped[bool | None] = mapped_column(Boolean)
    error_summary: Mapped[str | None] = mapped_column(String(1000))
    parameters_json: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, default=dict)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[str] = mapped_column(String(128), index=True)
    url: Mapped[str] = mapped_column(Text)
