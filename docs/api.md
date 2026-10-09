# API contract

The interactive OpenAPI document is available at `/api/docs` on the API port in local development. All stable routes use `/api/v1`.

## Core routes

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | Liveness/readiness summary |
| POST | `/api/v1/sensors/enroll` | Exchange enrollment secret for a sensor identity and ingestion token |
| GET | `/api/v1/sensors` | List sensor health and last-seen state |
| POST | `/api/v1/sensors/{id}/heartbeat` | Submit authenticated bounded sensor health telemetry |
| POST | `/api/v1/events/batch` | Submit an authenticated, idempotent normalized batch |
| GET | `/api/v1/events` | Paginated/filterable normalized events |
| GET | `/api/v1/alerts` | Paginated alert triage list |
| GET | `/api/v1/alerts/{id}` | Alert explanation and evidence |
| GET | `/api/v1/rules` | Loaded rule metadata and validation state |
| POST | `/api/v1/rules/reload` | Revalidate and atomically reload disk rules |
| GET | `/api/v1/scenarios` | Safe scenario catalog |
| POST | `/api/v1/scenarios/{id}/runs` | Record/launch a dry-run or lab-gated run |
| GET | `/api/v1/scenario-runs/pending` | Poll the next allowlisted run for the authenticated sensor |
| POST | `/api/v1/scenario-runs/{id}/status` | Claim a run and report cleanup-aware terminal status |
| POST | `/api/v1/demo/seed` | Seed deterministic synthetic telemetry |
| GET | `/api/v1/attack/coverage` | Rule/alert coverage by technique |
| GET | `/api/v1/timeline` | Bounded typed investigation graph |
| GET | `/api/v1/investigations/export` | JSON investigation package |
| POST | `/api/v1/maintenance/purge` | Retention purge with explicit confirmation |
| WS | `/api/v1/live` | Live invalidation/events feed |

## Ingestion invariants

- `Authorization: Bearer <sensor token>` is mandatory.
- Envelope `sensor_id` must match the token owner; events inherit that authenticated identity.
- `schema_version` must be supported by the API.
- `(sensor_id, batch_id)` makes retrying a successful batch safe.
- `(sensor_id, event_id)` prevents an event from being inserted through different batches.
- Partial success is not used. A malformed event rejects the batch before persistence.

Do not expose the API to an untrusted network without TLS termination and additional operator authentication. Sensor authentication protects ingestion; it is not a complete multi-user access-control model.
