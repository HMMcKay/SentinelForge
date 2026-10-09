# ADR 0001: Use a modular monolith

- Status: Accepted
- Date: 2026-07-27

## Context

The platform needs ingestion, detection, correlation, queries, live updates, and scenario bookkeeping. A broker plus independent services would make ordering, deployment, and incident debugging harder for a single-lab system.

## Decision

Run these responsibilities as explicit Python modules in one FastAPI process backed by PostgreSQL. Keep the sensor and browser as separate deployables because their platform and privilege boundaries are real. Expose module seams that can later become worker boundaries.

## Consequences

Local deployment and transaction handling remain simple. In-process correlation assumes one active evaluator, so horizontal API replicas are unsupported until ordered work claiming is added.
