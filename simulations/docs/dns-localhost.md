# DNS and localhost interaction

ATT&CK: T1071.004 as a telemetry analogue only. The scenario resolves the literal name `localhost`, creates an ephemeral listener bound to `127.0.0.1`, and exchanges the two fixed bytes `SF` with itself. It never resolves another name or contacts an external address. Loopback traffic is common; this exists to exercise graph linkage and near-miss handling rather than claim command-and-control equivalence.
