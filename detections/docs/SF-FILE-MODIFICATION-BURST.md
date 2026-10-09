# SF-FILE-MODIFICATION-BURST

Correlates five file create or modification events by the same process GUID and host within 30 seconds. Including `file_create` makes the rule usable with Sysmon Event ID 11 while synthetic demo data can use the more precise `file_modify` action. This is deliberately behavior-focused and does not assert encryption. Build, synchronization, and archival workloads can match. Maps to T1486.
