# SF-POWERSHELL-ENCODED

Detects encoded Windows PowerShell (`powershell.exe`) and PowerShell 7 (`pwsh.exe`) switches after normalization. The alert evidence preserves the complete originating event; the UI should not decode or execute the value. Legitimate automation is a known source of noise, so validate the parent, signer, payload contents, and surrounding activity. Maps to T1059.001 and command-obfuscation sub-technique T1027.010.
