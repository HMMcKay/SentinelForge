# Scoped registry Run-key pattern

ATT&CK: T1547.001 (Registry Run Keys / Startup Folder). The scenario writes one string beneath a per-run `HKCU\Software\SentinelForgeLab` key whose trailing components mirror `CurrentVersion\Run`. This produces registry-create/set telemetry but is not an OS-interpreted autostart location and does not establish persistence. Cleanup deletes only the exact per-run SentinelForgeLab key. Expected false positives include installers and user applications legitimately updating real Run keys; path context and value signer are important during triage.
