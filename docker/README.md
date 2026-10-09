# Container notes

The canonical deployment definition is [`../compose.yaml`](../compose.yaml). PostgreSQL is attached only to the internal `data` network. The API and UI bind to `127.0.0.1` by default; change `SENTINELFORGE_BIND_ADDRESS` only when another trusted lab host must connect.

The Windows sensor is deliberately not placed in the Linux Compose stack. It reads host Event Log APIs and therefore runs directly in the isolated Windows VM. `sentinelctl` is provided as an on-demand Compose profile so it does not consume resources when idle.
