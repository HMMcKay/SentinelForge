# Synthetic security-control modification

ATT&CK: T1685 (Disable or Modify Tools). The `security-control-events` scenario writes a normalized `security_control` JSON event with boolean `synthetic=true`, `action=disable`, and boolean `operating_system_modified=false`. It does not query, disable, or modify Defender, the registry, services, firewall, audit policy, or another control. The authenticated lab runner uploads only this fixed event shape; consumers must keep its synthetic marker visible so it is never represented as an observed control change.
