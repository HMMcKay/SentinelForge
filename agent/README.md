# SentinelForge Windows sensor

The sensor is a .NET 8 Worker that reads `Microsoft-Windows-Sysmon/Operational`, converts supported records into the SentinelForge `1.0` event envelope, persists each outbound batch before advancing its event-log cursor, and uploads batches with bearer authentication. It can run interactively or under the Windows Service Control Manager.

The sensor is intentionally host-run rather than containerized. A Windows container cannot observe the host's Sysmon channel without breaking the isolation boundary the project is meant to preserve. The backend, database, and dashboard run in Docker; this process runs only in the explicitly isolated Windows lab VM.

## Security boundaries

- Enrollment credentials and ingestion tokens are never written to logs.
- On Windows, the persisted identity is encrypted with DPAPI `CurrentUser`. Install and operate the service under the same dedicated low-privilege account. Changing that identity makes the token unreadable; because version 0.1 has no rotation endpoint, an operator must reset or repair the lab-side enrollment record before recreating enrollment.
- The non-Windows identity fallback is plaintext and hard-disabled unless `AllowPlaintextIdentityForTests=true`. It exists only for CI and local interface tests, not deployment.
- Plain HTTP is accepted by default only for loopback. A remote HTTP endpoint requires the conspicuous `AllowInsecureHttp=true` override; HTTPS should be used across VM boundaries.
- The on-disk spool is bounded. When full, it drops the oldest complete batch, increments `dropped_batches`, and emits a structured warning. It never grows without limit.
- A permanently invalid batch (HTTP 4xx other than 408/429) is removed so one bad payload cannot block collection forever. The rejection is counted in local health telemetry.
- Raw Sysmon XML is parsed with DTDs and external entity resolution disabled, but is neither uploaded nor logged. The normalized source channel and record ID preserve the lookup reference without duplicating sensitive raw payloads.

## Build and test

```powershell
dotnet restore .\agent\SentinelForge.Agent.sln --locked-mode
dotnet test .\agent\SentinelForge.Agent.sln --configuration Release --no-restore
dotnet publish .\agent\src\SentinelForge.Agent\SentinelForge.Agent.csproj -c Release -r win-x64 --self-contained false
```

The supported runtime is .NET 8. Sysmon must be installed separately and the service account needs read access to its Operational event channel.

## Configure

Copy `src/SentinelForge.Agent/appsettings.json` beside the executable and set either an enrollment token or a pre-provisioned sensor ID/token. Environment variables use the `SENTINELFORGE_` prefix and .NET's double-underscore nesting:

```powershell
$env:SENTINELFORGE_Agent__BaseUrl = 'https://10.10.10.5:8443'
$env:SENTINELFORGE_Agent__EnrollmentToken = '<one-time enrollment token>'
dotnet run --project .\agent\src\SentinelForge.Agent
```

After first enrollment, remove the enrollment token. The DPAPI-protected identity is reused. The default data locations are under `%ProgramData%\SentinelForge` and can be changed independently. `IngestionPath`, `EnrollmentPath`, and `HeartbeatPathTemplate` are configurable to support reverse-proxy prefixes.

For a cross-platform smoke run, set `EventSource=idle`, use temporary paths, and explicitly enable the plaintext test identity fallback. That mode does not read events and must not be used for a real sensor.

## Windows service mode

Publish first, then create the service from an elevated PowerShell prompt. Use a dedicated service account and grant it `Read` access to the Sysmon event channel and `Modify` access only to the configured SentinelForge data directory.

```powershell
sc.exe create SentinelForgeSensor binPath= "C:\SentinelForge\agent\SentinelForge.Agent.exe" start= demand
sc.exe start SentinelForgeSensor
sc.exe query SentinelForgeSensor
```

Keep network ACLs restricted to the backend ingestion address. Interactive execution and service execution share the same worker code; `AddWindowsService` activates SCM lifetime behavior only when launched as a service.

## Operational telemetry

The sensor writes an atomic `health.json` snapshot and periodically posts the same strict payload to `/api/v1/sensors/{sensor_id}/heartbeat`. It reports agent/service mode, last event time, exact spooled event/byte counts, and bounded redacted error codes. Spool drops and backend rejections appear as durable error codes. JSON console logging works with both interactive collection and standard Windows service log capture.

## Supported Sysmon mappings

The normalizer provides explicit mappings for process create/terminate (1/5), network connect (3), file create/delete (11/23/26), registry create/set/delete/rename telemetry (12/13/14), and DNS query (22). Sysmon IDs outside this validated subset are skipped, counted as a redacted normalization health error, and never uploaded as an invented generic type. Detection logic remains in the backend so sensor upgrades are not required for rule changes.

Scenario attribution first accepts a valid explicit `ScenarioRunId` field, then looks for a hyphenated UUID only inside an observable `SentinelForgeLab\Runs\<uuid>` path or allowlisted task-name shape in Sysmon target, image, or command fields. Bare UUIDs and lookalike namespaces are ignored. Encoded PowerShell (where the marker path exists only in the child environment) and DNS-only activity can therefore remain untagged; correlation still uses process and time evidence without inventing a scenario edge.
