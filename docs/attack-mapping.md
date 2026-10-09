# ATT&CK mapping

SentinelForge uses ATT&CK identifiers as a common vocabulary for the behavior a rule or scenario is intended to exercise. A mapping is not a claim that the project detects every implementation of a technique, prevents it, or reproduces an adversary procedure.

The built-in catalog is deliberately small and source-linked:

| Technique | Name | Where used | Scope note |
|---|---|---|---|
| [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | Obfuscated Files or Information: Command Obfuscation | Encoded PowerShell | A fixed benign Base64-encoded command only |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | Named scheduled-task scenario/rule | SentinelForge-specific task, followed by cleanup |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Encoded command and process sequence | Interpreter behavior, not payload behavior |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Command and Scripting Interpreter: Windows Command Shell | Benign process chain | Fixed echo/child lineage only |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | DNS/localhost scenario | Reserved/test lookup and loopback interaction only; no command-and-control server |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | User-writable execution rule/scenario | Behavioral approximation only: the file is benign and the automated scenario does not reproduce a deceived user |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Synthetic file-modification burst | Generated sandbox files only; no real encryption or impact |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Run-key scenario/rule | The live scenario writes beneath a non-autostart SentinelForge key whose suffix has the Run-key telemetry shape; the demo event exercises the canonical path |
| [T1685](https://attack.mitre.org/techniques/T1685/) | Disable or Modify Tools | Synthetic control-change event | Telemetry only; no security control is changed |

Coverage view counts separate concepts:

- **rule coverage**: at least one enabled rule maps to the technique;
- **observed events**: normalized events carry the tag;
- **alerts**: a mapped rule actually fired.

Those counts should not be collapsed into a single percentage. The platform does not calculate an ATT&CK coverage score because the denominator and quality of a technique-level detection are not interchangeable.
