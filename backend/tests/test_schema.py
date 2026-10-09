from __future__ import annotations

from sqlalchemy import inspect


def test_database_has_required_tables_and_indexes(client) -> None:
    inspector = inspect(client.app.state.database.engine)
    tables = set(inspector.get_table_names())
    assert {
        "sensors",
        "hosts",
        "sensor_health",
        "raw_events",
        "normalized_events",
        "process_activity",
        "network_activity",
        "file_activity",
        "registry_activity",
        "detection_rules",
        "rule_versions",
        "alerts",
        "alert_evidence",
        "correlation_groups",
        "scenarios",
        "scenario_runs",
        "attack_techniques",
    } <= tables
    event_indexes = {index["name"] for index in inspector.get_indexes("normalized_events")}
    assert "ix_event_time_host" in event_indexes
    assert "ix_event_process_guid" in event_indexes
    assert "ix_event_scenario_time" in event_indexes
    assert "ix_event_attack_tags_gin" in event_indexes
    rule_indexes = {index["name"] for index in inspector.get_indexes("detection_rules")}
    alert_indexes = {index["name"] for index in inspector.get_indexes("alerts")}
    assert "ix_rule_attack_tags_gin" in rule_indexes
    assert "ix_alert_attack_tags_gin" in alert_indexes
