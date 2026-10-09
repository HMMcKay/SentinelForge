# Publication checks — October 8, 2026

These checks were executed locally while preparing the first full-project GitHub commit. They supplement, rather than replace, the [July 27 validation record](validation-report.md).

## Executed checks

| Boundary | Check | Observed result |
|---|---|---|
| Backend | Python 3.12.13 pytest suite | 29 passed |
| CLI | Python 3.12.13 pytest suite | 4 passed |
| Rules | `sentinelctl rules validate detections/rules` | 7 rules accepted |
| Python source | Ruff against backend, CLI, and publication checks | Passed |
| Frontend | ESLint and Vitest | Lint passed; 14 tests passed |
| Frontend | TypeScript/Vite production build | Passed |
| Browser | Local Playwright suite with mocked API | 4 passed; live-stack test skipped without a running backend |
| Windows sensor | Locked NuGet restore and Release xUnit suite | 22 passed |
| Simulations | PowerShell containment/safety suite | 46 assertions passed |
| Deployment configuration | `docker compose config --quiet` | Passed |
| Project page | Static resources, anchors, stage IDs, DOM references, screenshot hashes | Passed |
| Project page | JavaScript syntax check | Passed |
| Project page | Chromium desktop (1440×1000) and mobile (390×844) review | No page-wide horizontal overflow; diagram scroll is contained |
| Project page | Workflow stages, image dialog, Escape dismissal, clipboard control | Exercised successfully |
| Project page | Browser console during interaction checks | No errors or warnings reported |
| Publication | Git index review | Private/generated paths excluded; no local `.env` credentials or common token/private-key patterns found |

The local Python environments had stale interpreter paths from the repository's previous location. A fresh verification environment was created under ignored `output/`; existing environments were not removed. Third-party deprecation warnings from the FastAPI/Starlette test client and Typer/Click were visible; they did not cause test failures.

The publication review also found that a broad `spool/` ignore pattern hid the sensor's `Spool` source directory on a case-insensitive Windows checkout. The rule now targets root runtime spool data only, and all four sensor spool source files are included.

## Not re-executed locally

Docker Desktop's Linux engine was unavailable, so this pass did not rebuild images, start the Compose stack, or repeat the live PostgreSQL/browser flow. The container and live-stack results in the earlier report remain dated historical evidence. [GitHub Actions](https://github.com/HMMcKay/SentinelForge/actions) is the authoritative record for hosted checks on published commits.

Real Sysmon collection, Windows service installation, final service-identity DPAPI behavior, and non-dry live simulations were not exercised. The checks above do not establish those integrations or production readiness.

The pre-publication credential check is intentionally narrow. It is useful for catching local secrets and common token shapes, not proof that every possible sensitive value is absent.

## Hosted checks for the initial project commit

Commit [`25be303`](https://github.com/HMMcKay/SentinelForge/commit/25be3034bde800254b0a58ef089a943b9ad3ec74) was pushed during this publication pass. The [CI run](https://github.com/HMMcKay/SentinelForge/actions/runs/37871223926) passed backend, frontend, CLI, sensor, scenario-safety, all four container builds, and the live Compose/browser flow. The [supply-chain run](https://github.com/HMMcKay/SentinelForge/actions/runs/37871223962) passed dependency audits and SBOM generation; dependency review was skipped because this was a push rather than a pull request.

The [initial CodeQL run](https://github.com/HMMcKay/SentinelForge/actions/runs/37871223931) completed all three language analyses and flagged the credential check's reporting path as possible clear-text logging. That path reported key names rather than credential values. The reporting now includes only staged filenames, with synthetic regression tests covering omission of both keys and values. The current CodeQL alert state should be checked in the repository's Security tab rather than inferred from a successful analysis job.
