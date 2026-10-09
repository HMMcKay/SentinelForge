# Contributing

Contributions should improve a working, testable behavior. A broad rule collection without fixtures, or a simulation without verified cleanup, is not ready to merge.

## Before opening a change

1. Read the architecture decision records and threat model.
2. Keep changes inside the existing trust boundaries unless the change also includes an ADR.
3. Do not use production telemetry. Build minimal synthetic fixtures with stable IDs and timestamps.
4. For detections, add positive and near-miss regression cases plus rule documentation.
5. For simulations, add dry-run output, a cleanup manifest, cleanup verification, and containment tests.
6. For schema changes, preserve `1.x` compatibility or introduce a separately versioned contract.

## Local checks

```powershell
./scripts/bootstrap.ps1 -NoStart
pwsh -NoProfile -File scripts/validate.ps1
```

Focused commands are listed in `docs/development.md`. Windows Event Log integration tests require an isolated VM and must not be run on a personal or production endpoint.

## Pull requests

Keep the pull request small enough to review. Explain the behavioral change, security impact, test evidence actually produced, and anything that was not run. Never paste sensor tokens, `.env` files, command lines containing secrets, private exports, or host-identifying telemetry.

All GitHub Actions are pinned to full commit SHAs. When updating one, verify the upstream tag and update the adjacent version comment in the same change.
