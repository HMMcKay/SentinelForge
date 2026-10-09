# Threat model

This model treats SentinelForge as a security-sensitive lab application, not as a security control. The primary assets are ingestion credentials, event integrity, operator intent, the Windows VM, database contents, and the simulation safety boundary.

## Trust boundaries

1. Sysmon XML enters the sensor as untrusted structured input.
2. The Windows sensor crosses the VM-to-Compose network with authenticated batches.
3. Browser and CLI input cross the API boundary.
4. The API is the only process that crosses from the edge network to the database network.
5. A simulation crosses from declarative scenario metadata into constrained host changes.

## STRIDE analysis

| Threat | Example | Mitigation | Residual risk |
|---|---|---|---|
| Spoofing | An arbitrary host submits events as a sensor | One-time enrollment secret; independent high-entropy bearer token per sensor; stored token digest; TLS required beyond loopback | A stolen live token can submit until revoked |
| Tampering | Events or cleanup manifests are altered | TLS; strict schema; IDs scoped to sensor; append-oriented evidence; simulation containment checks | A privileged VM administrator can alter local spool or telemetry |
| Repudiation | Operator denies starting a scenario or purging data | Scenario run/audit records; structured request IDs; explicit CLI confirmation for purge | This is not a WORM audit system |
| Information disclosure | Command lines contain secrets | Log field allowlist/redaction; UI escaping; exports are operator-requested; loopback binding | Telemetry itself can contain sensitive data and must be handled accordingly |
| Denial of service | Huge batches, graph queries, or spool growth exhaust resources | Body and item limits; database indexes; bounded timeline; pagination; bounded spool; retention | A valid sensor can still generate enough legitimate telemetry to pressure a small lab host |
| Elevation of privilege | UI input causes host command execution | API never accepts arbitrary commands; scenario IDs map to allowlisted definitions; host runner enforces lab gate and containment | Compromise of the Windows service account inherits that account's rights |

## Abuse cases

### Forged detection evidence

A sensor can lie about the events it observed. SentinelForge proves rule behavior against received telemetry; it does not attest to sensor or kernel integrity. For high-assurance research, compare event-log integrity and VM snapshots outside the platform.

### Simulation escape

Every scenario must pass `SENTINELFORGE_LAB_MODE=1`, resolves its sandbox path, supports dry-run, records each created artifact, and verifies cleanup. Registry and task scenarios use SentinelForge-specific names. The ransomware-behavior emulator transforms only files it created beneath its sandbox. The runner rejects volume roots, UNC paths, containment escapes, tampered manifest targets, and reparse points at the checked sandbox boundaries.

### Stored content injection

Event fields are rendered as text, never HTML. Query construction uses SQLAlchemy parameters. Exports serialize JSON rather than templating event content into executable formats. Nginx and the API set conservative response headers.

## Security assumptions

- The lab network is isolated and trusted operators control the host.
- TLS is terminated by a trusted lab reverse proxy when the sensor is remote; the built-in loopback deployment does not provide certificates.
- Docker and the Windows VM administrator are trusted computing-base components.
- Sysmon is installed and configured separately; SentinelForge does not weaken its configuration.

## Security review checklist

- Validate changed schema and rule fixtures.
- Add a negative test for every new rule operator.
- Review simulation paths and cleanup together.
- Confirm no service publishes PostgreSQL.
- Rotate enrollment credentials before shared demos.
- Inspect dependency and CodeQL findings; do not treat scanner success as proof of safety.
