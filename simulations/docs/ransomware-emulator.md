# Synthetic ransomware behavior

ATT&CK: T1486 (Data Encrypted for Impact). The `ransomware-emulator` scenario accepts no input directory. It creates twelve marked sample files inside the run directory, hashes and backs them up, applies a fixed reversible XOR transform, and renames them with `.sf_locked`. It verifies the synthetic marker before every transform and never enumerates outside its generated file list. Cleanup removes the generated directory. This demonstrates burst/rename telemetry, not real encryption, propagation, recovery impact, or ransomware capability.
