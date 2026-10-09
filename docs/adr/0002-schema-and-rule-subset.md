# ADR 0002: Own a versioned event contract and a strict Sigma subset

- Status: Accepted
- Date: 2026-07-27

## Context

Sysmon field names vary by event ID and version. Sigma is a portable rule format, not a runtime evaluator specification, and silently approximating unsupported operators would make regression tests misleading.

## Decision

Normalize at the sensor/API boundary into SentinelForge schema `1.0.0`. Accept extensions only in `metadata`. Implement and document an allowlisted Sigma-like subset and reject unsupported aggregation, pipeline, backend-specific modifiers, and malformed conditions during rule loading.

## Consequences

Rules are deterministic and explainable, but arbitrary community Sigma rules cannot be dropped in without adaptation. Schema-breaking changes require a new major version and an explicit migration path.
