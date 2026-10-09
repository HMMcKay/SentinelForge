# User-writable execution

ATT&CK: T1204.002. The scenario copies the system `cmd.exe` into its own user-writable run directory and executes only `/d /c exit 0`. It downloads nothing and passes no user-controlled command. Cleanup removes the copied executable. Legitimate portable tools and development builds also execute from user-writable paths, so signer/hash, provenance, parent process, and follow-on behavior matter.
