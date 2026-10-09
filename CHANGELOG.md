# Changelog

All notable changes are documented here. The project follows Keep a Changelog conventions and uses semantic versioning after the initial development series.

## [Unreleased]

### Added

- Static GitHub Pages project explanation with real dashboard captures, a component diagram, an interactive detection-path walkthrough, and source-linked engineering notes.
- SHA-pinned Pages deployment and dependency-free page/publication checks.
- Dated local publication validation report.

### Fixed

- Scoped the runtime spool ignore rule so Windows checkouts include the sensor's `Spool` source directory.
- Added locked sensor restore before the hosted NuGet vulnerability query.

## [0.1.0] - 2026-07-27

### Added

- Docker-first FastAPI, PostgreSQL, React/Nginx, and `sentinelctl` deployment.
- Versioned normalized event and authenticated/idempotent batch-ingestion contracts.
- Strict Sigma-subset evaluation, stateful correlation, evidence-backed alerts, and rule regression fixtures.
- Deterministic Windows-free demo dataset with positive and near-miss activity.
- SOC overview, triage, rule, scenario, ATT&CK coverage, and forensic timeline views.
- .NET Windows sensor with Sysmon abstraction, bounded spool, retry, identity protection, and tests.
- Lab-gated, dry-run, reversible PowerShell simulation framework and safety tests.
- Threat model, ADRs, operations guidance, contributor/security policy, and private owner guide.
- Pinned CI, CodeQL, dependency review, SBOM generation, and container build workflows.
