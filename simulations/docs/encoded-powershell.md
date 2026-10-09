# Benign encoded PowerShell

ATT&CK: T1059.001 and T1027.010 (Command Obfuscation). A fixed UTF-16LE `-EncodedCommand` writes one known marker using a path passed through the child environment. No supplied string enters the encoded payload. Cleanup deletes the marker. Encoded PowerShell is used by management products as well as attackers; decode it and correlate the parent, signer, destination paths, and network behavior.
