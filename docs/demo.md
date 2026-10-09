# Deterministic demo

The demo path exercises ingestion-independent normalization, detection, correlation, alert explanation, ATT&CK coverage, and timeline rendering. It does not require Windows or Sysmon.

```powershell
./scripts/bootstrap.ps1
docker compose --profile tools run --rm sentinelctl demo seed --seed 1337
Start-Process http://127.0.0.1:8080
```

The seed is deterministic: stable identifiers, timestamps relative to a fixed epoch, host/user/process relationships, positive cases, and near misses. Running the same seed again is idempotent. Choose another seed to create a distinct dataset.

Suggested review path:

1. Confirm service and sensor state on Overview.
2. Open Alerts and select an alert to read its matched fields and evidence IDs.
3. Compare the related near-miss event in the event list.
4. Open the timeline, filter to the alert's technique, and select the alert node.
5. Use replay to watch the evidence chain develop in event-time order.
6. Review the rule and its false-positive notes.
7. Open ATT&CK Coverage to distinguish implemented rules from observed alerts.
