# Validation report

This report records checks actually executed against the repository state produced on 2026-07-27. It is not a claim about future commits, other Windows releases, or an internet-facing deployment.

## Environment

- Windows host with Docker Desktop 29.4.3
- Docker Compose v2
- .NET SDK 9.0.316, targeting .NET 8 for the sensor
- Node.js 26.2.0 and npm 11.13.0 for host checks; Node 24.18.0 in the build image
- Python 3.12.13 in the project environment and runtime images
- PostgreSQL 17.10 container
- Playwright 1.62.0 with Chromium 151.0.7922.34

## Repository tree

```text
SentinelForge/
├── .github/        CI, CodeQL, supply-chain audit, Dependabot
├── agent/          .NET Windows sensor and xUnit tests
├── backend/        FastAPI service, SQLAlchemy model, Alembic, pytest
├── cli/            sentinelctl client and tests
├── detections/     seven rules and per-rule documentation
├── docker/         pinned PostgreSQL image support
├── docs/           architecture, ADRs, threat model, runbooks, real screenshots
├── frontend/       React dashboard, Cytoscape timeline, Vitest, Playwright, Nginx
├── schemas/        versioned JSON schemas and example event
├── scripts/        bootstrap and complete validation workflows
├── simulations/    eight contained scenarios, runner, cleanup, safety tests
├── private/        ignored owner guide (present locally, not publishable)
├── compose.yaml
└── compose.test.yaml
```

## Checks that passed

| Area | Executed check | Result |
|---|---|---|
| Backend | Host pytest suite | 29 passed |
| Backend | Ruff | Passed |
| Backend | Rebuilt Docker test image and pytest | 29 passed |
| CLI | Host pytest suite and Ruff | 4 passed; lint passed |
| CLI | Docker test image | 4 passed |
| Rules | `sentinelctl rules validate` | 7 rules accepted; no unsupported features |
| Frontend | ESLint, Vitest, TypeScript/Vite build | Lint passed; 14 tests passed; production build passed |
| Frontend | Rebuilt Docker test image and Vitest | 14 passed |
| Browser | Playwright mocked and live-stack flows | 5 passed |
| Sensor | Locked restore and Release xUnit suite | 22 passed |
| Simulations | PowerShell safety suite | 46 assertions passed |
| Simulations | PowerShell parser validation | Passed |
| Sensor packaging | `dotnet publish` | Passed; generated artifacts removed afterward |
| Developer workflow | `pwsh -NoProfile -File scripts/validate.ps1` | Passed end to end |
| Configuration | Public JSON files and workflow YAML parse | Passed |
| Configuration | Production and test Compose resolution | Passed |
| Database | Alembic against live PostgreSQL | Head `20260727_0001` |
| Database | Live schema inspection | 18 application tables plus Alembic metadata; 3 GIN indexes |
| Supply chain | `pip-audit` for backend and CLI locks | No known vulnerabilities after framework upgrade |
| Supply chain | NuGet transitive vulnerability query | No vulnerable packages reported |
| Supply chain | npm audit at high threshold | No high or critical findings |

The first Python audit identified six advisories inherited through Starlette 0.47.3. FastAPI, Pydantic, and Starlette were upgraded to the compatible 0.140.7, 2.13.4, and 1.3.1 releases; the backend suite, image build, live stack, and audit were then rerun successfully.

The frontend audit still reports two moderate React Router 6 advisories with no available fix on that branch: a backslash redirect issue and an SSR hydration constructor-injection issue. SentinelForge is a client-only SPA, does not use React Router SSR/data-router deserialization, and constructs navigation targets from fixed local routes or URL-encoded backend identifiers. They remain tracked residual dependency risk rather than being hidden.

## Live-stack validation

The complete Compose stack was built and started with PostgreSQL, FastAPI, and unprivileged Nginx all reporting healthy. PostgreSQL was not published to the host; the API and UI were bound to loopback.

`sentinelctl demo seed --seed 1337` produced 19 normalized events and 7 alerts. Repeating the command returned `idempotent_replay: true` and no new alert identifiers. Live API inspection found evidence on alert detail responses and a forensic timeline containing 27 nodes and 39 typed edges. The browser saw 19 events, 7 alerts, one reporting sensor, 8 of 9 cataloged techniques covered by rules, and a connected live feed.

The final unmocked browser test loaded this live stack, asserted the seeded overview, navigated to the graph, found a non-empty accessible timeline representation, and verified the Nginx CSP, frame-denial, and MIME-sniffing headers. A separate Playwright semantic/visual pass found no browser console errors or warnings. The screenshots in `docs/assets/` were captured from that running stack.

Direct HTTP checks also confirmed:

- unauthenticated enrollment and purge requests return 401;
- the API emits `X-Content-Type-Options: nosniff`;
- HTML emits CSP, `X-Frame-Options: DENY`, `nosniff`, and `Cache-Control: no-store`;
- immutable static assets retain the same security headers.

## Not verified here

- Reading a real Sysmon Operational channel in a provisioned Windows VM
- DPAPI behavior under the final Windows service identity and loaded service profile
- Windows Service Control Manager installation and recovery behavior
- Actual Task Scheduler registration or live registry writes; the safety framework and cleanup logic were tested without treating portable checks as live integration proof
- A non-dry lab-runner execution against the backend
- TLS reverse-proxy deployment, enterprise identity, multi-user RBAC, or internet exposure
- Multiple concurrent API replicas; correlation state is intentionally single-instance in version 0.1
- Sustained load, high-cardinality hosts, long-duration retention, or benchmark claims
- CodeQL analysis, GitHub dependency review, and SBOM artifact generation on GitHub Actions; their pinned workflow definitions were parsed locally but require a GitHub run
- Container CVE scanning beyond the dependency audits above

## Known validation notes

Starlette 1.3.1 emits an upstream deprecation warning when FastAPI's current `TestClient` uses `httpx`; it does not fail the suite. React Router 6 emits its documented future-flag warnings in component tests. Neither warning was present in the production browser console.

The stack was left running and healthy after validation so the seeded dashboard remains available at `http://127.0.0.1:8080`. Use `docker compose down` to stop it without removing the database volume.
