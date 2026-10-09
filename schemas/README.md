# SentinelForge event contracts

`normalized-event-v1.schema.json` is the public interchange contract selected by batch `schema_version: 1.0`. Producers may add fields only beneath `metadata`; incompatible top-level changes require a new major schema version. Timestamps are UTC RFC 3339 values. Sensor identity is carried by the batch envelope, and server ingest time is authoritative. A batch is idempotent by `(sensor_id, batch_id)`, while an individual event is idempotent by `(sensor_id, event_id)`.

The schema borrows familiar naming from ECS and OCSF but intentionally does not claim conformance to either standard.
