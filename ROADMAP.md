# Roadmap

This roadmap is directional, not a promise of dates.

## Near term

- Add signed sensor enrollment requests and explicit token revocation UI.
- Expand the supported Sigma subset only where semantics can remain deterministic.
- Persist operator audit identities after adding a real local authentication model.
- Add more correlation regression corpora and property-based normalization tests.
- Package the Windows worker as a signed MSI with rollback-aware upgrades.
- Add a TLS reference deployment for a two-VM isolated lab.

## Later

- Database-backed work claiming for safe multi-instance detection evaluation.
- Import/export for investigation bundles with integrity manifests.
- Schema adapters for selected Windows Security and PowerShell Operational events.
- ATT&CK release metadata ingestion with license/source attribution and version pinning.
- Server-side timeline aggregation for longer retention windows.
- Optional OpenTelemetry metrics without exporting sensitive event fields.

## Explicitly not planned

- Offensive payloads, credential access, evasion, or persistence outside named test artifacts.
- Pretending to replace an EDR, SIEM, or forensic acquisition platform.
- Silent compatibility with arbitrary community Sigma backends.
- Internet-facing multi-tenancy without a separate authentication/authorization design.
