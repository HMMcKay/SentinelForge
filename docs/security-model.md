# Security model

SentinelForge's safe default is an offline demonstration: services bind to loopback, lab mode is disabled, the database has no published port, and scenario requests default to dry-run. These defaults are enforced at separate layers so one UI mistake cannot enable execution.

## Credentials

- `POSTGRES_PASSWORD` and `SENTINELFORGE_ENROLLMENT_KEY` are supplied through `.env`, which is ignored. The bootstrap script generates independent random local values.
- A sensor exchanges the enrollment secret once for a unique ingestion token. The API stores a cryptographic digest, not the bearer value.
- The sensor protects its identity material with Windows DPAPI. The non-Windows development fallback is test-only and explicitly marked.
- Credentials and authorization headers must not appear in structured logs.

## Network exposure

The UI is published on `127.0.0.1:8080` and the API on `127.0.0.1:8000`. PostgreSQL is reachable only from the internal Compose network. Remote sensor use requires an operator-managed TLS reverse proxy and firewall rule scoped to the lab network.

## Input and output handling

Pydantic models and the versioned JSON Schema constrain event structure, lengths, counts, and scalar types. Batch, request-body, pagination, and graph limits are enforced server-side. SQLAlchemy binds query values. React escapes event strings by default; no raw HTML path is used.

## Service privilege

Linux containers drop all capabilities and set `no-new-privileges`. Images run as non-root where their service implementation permits it. The Windows service should use a dedicated virtual or managed service account with Event Log read access, a private spool directory, and no interactive logon.

## Lab mode

Enabling lab mode authorizes only the allowlisted, reversible scenario implementations. It does not accept arbitrary PowerShell, process paths, registry keys, task names, or target directories from the API. The Windows-side runner independently enforces its environment flag and sandbox constraints.
