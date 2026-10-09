# Safe lab simulations

These PowerShell scenarios create narrow, observable behaviors for SentinelForge in a disposable lab. They are not exploitation modules. Every entry point checks `SENTINELFORGE_LAB_MODE=1`, accepts only IDs in `catalog.json`, computes a per-run directory, writes a cleanup manifest before external state changes, and rejects cleanup targets outside strict filesystem/registry/task allowlists.

## Run directly

```powershell
$env:SENTINELFORGE_LAB_MODE = '1'
pwsh -NoProfile -File .\simulations\Invoke-SentinelForgeScenario.ps1 `
  -ScenarioId encoded-powershell -DryRun

pwsh -NoProfile -File .\simulations\Invoke-SentinelForgeScenario.ps1 `
  -ScenarioId encoded-powershell -RunId lab-demo-01

pwsh -NoProfile -File .\simulations\Cleanup-SentinelForgeScenario.ps1 `
  -ManifestPath "$env:TEMP\SentinelForgeLab\runs\lab-demo-01\cleanup-manifest.json"
```

Dry runs require lab mode too, but make no files, processes, registry keys, tasks, or network connections. A real run refuses to reuse a run ID until its earlier manifest is cleaned.

The Run-key scenario deliberately uses `HKCU\Software\SentinelForgeLab\Runs\<run>\Software\Microsoft\Windows\CurrentVersion\Run`. Its suffix is Run-key-shaped for registry telemetry, but Windows does not interpret it as an autostart location. The task scenario is the sole actual persistence-shaped object: `schtasks.exe /Create` consumes contained fixed XML whose task and far-future trigger are disabled, the task lives under `\SentinelForgeLab\`, its fixed action is `cmd.exe /d /c exit 0`, and the manifest removes it. Neither scenario targets a production persistence location.

The ransomware behavior scenario refuses any input files. It generates files carrying the `SENTINELFORGE_SYNTHETIC_V1` marker under its own run directory, verifies that marker before transformation, retains verified backups, and then removes the entire generated run directory during cleanup. It cannot be pointed at another directory.

## Dashboard lab runner

`Start-SentinelForgeLabRunner.ps1` is a separate, opt-in process. The read-only sensor never executes scenarios. The runner polls the sensor-authenticated pending-run endpoint, checks the local catalog again, accepts no command or path from the backend, executes with automatic cleanup, and reports a terminal status only after cleanup verification.

```powershell
$env:SENTINELFORGE_LAB_MODE = '1'
$env:SENTINELFORGE_SENSOR_TOKEN = '<sensor ingestion token>'
pwsh -NoProfile -File .\simulations\Start-SentinelForgeLabRunner.ps1 `
  -BaseUrl https://10.10.10.5:8443
```

HTTP is limited to loopback unless `-AllowInsecureHttp` is deliberately provided. The runner should use the same low-privilege lab identity as the sensor only if that identity has the narrowly required task/registry permissions. Prefer a separate low-privilege account and token where the deployment supports it.

Run one lab-runner process per sensor identity. The backend status transition is also used as an atomic claim: if another runner has already moved a request to `running`, a `409 Conflict` makes this runner skip it without executing or posting a failure.

## Cleanup model

Manifests support only four action types:

- delete the exact per-run directory;
- delete the exact `HKCU\Software\SentinelForgeLab\Runs\<run>` key;
- unregister a task whose path is exactly `\SentinelForgeLab\` and whose name begins with the validated run ID.
- restore only manifest-listed, generated synthetic files from hash-verified backups inside the same run directory.

Unknown action types and tampered paths fail closed. Cleanup is available even after lab mode is unset so an operator cannot strand a lab artifact by clearing the gate. If an action fails, the run directory and manifest remain for inspection.

## Test

No gallery dependency is required:

```powershell
pwsh -NoLogo -NoProfile -File .\simulations\tests\Run-SafetyTests.ps1
```

The test script checks the lab gate, catalog allowlist, dry-run non-mutation, sibling-path traversal, manifest tampering, outside-canary integrity, automatic cleanup, local-only networking, synthetic file transformation, and safe process scenarios. Registry and Task Scheduler integration are intentionally left for a disposable Windows lab because host policy commonly blocks them in CI.

## Scenario reference

- [Registry Run-key pattern](docs/registry-run-key.md)
- [Scheduled task](docs/scheduled-task.md)
- [Benign process chain](docs/benign-process-chain.md)
- [Encoded PowerShell](docs/encoded-powershell.md)
- [User-writable execution](docs/user-writable-execution.md)
- [DNS and localhost](docs/dns-localhost.md)
- [Synthetic ransomware behavior](docs/ransomware-emulator.md)
- [Synthetic security-control event](docs/security-control-events.md)
