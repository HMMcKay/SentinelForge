# Development

## Prerequisites

- Docker Engine/Desktop with Compose v2
- Node.js 24+ for direct frontend work
- Python 3.12+ for direct backend work (Docker is sufficient)
- .NET 8 SDK or newer for the sensor
- PowerShell 7 for scenario tests and scripts

## Test layers

```powershell
pwsh -NoProfile -File scripts/validate.ps1
npm --prefix frontend test -- --run
npm --prefix frontend run build
dotnet test agent/SentinelForge.Agent.sln --configuration Release
pwsh -NoProfile -File simulations/tests/Run-SafetyTests.ps1
```

By default, Playwright starts a built frontend preview and runs deterministic contract-fixture flows. CI additionally starts and seeds Compose, sets `PLAYWRIGHT_BASE_URL=http://127.0.0.1:8080`, and runs the unmocked live-stack check. Windows integration tests that read the real Sysmon channel are intentionally separate from portable unit tests and require an explicitly provisioned lab VM.

## Repository standards

- Treat event and API contract changes as versioned interfaces.
- Keep rule fixtures deterministic.
- Pair every simulation action with cleanup and cleanup verification.
- Do not commit `.env`, sensor identities, exports, event captures, or anything beneath `private/`.
- Pin direct dependencies and GitHub Actions. Dependabot proposes reviewed updates.
- Record an ADR when changing a trust boundary, persistence model, or compatibility promise.
