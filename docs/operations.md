# Operations runbook

## Start and inspect

```powershell
./scripts/bootstrap.ps1
docker compose ps
docker compose logs --tail 100 backend frontend database
```

Healthy services report `healthy` in Compose. The UI's `/healthz` checks Nginx; the API `/health` checks application readiness. Database migrations run before the API accepts traffic.

## Stop, retain, or remove data

`docker compose down` stops containers and retains the named database volume. `docker compose down --volumes` permanently removes local database data and must be used only when the target Compose project is confirmed. Scenario artifacts live in the Windows sandbox and are removed by the scenario cleanup command, not by Docker.

## Back up

Use `pg_dump` through the database container and place output in a protected directory outside the repository. Investigation exports are evidence conveniences, not database backups and not cryptographically sealed forensic images.

## Sensor problems

- Enrollment 401: confirm the API and sensor use the same enrollment secret, then rotate the secret if it may have leaked.
- Ingestion 401: verify that the service still uses the Windows identity that owns the DPAPI-protected token and do not paste the bearer value into logs or issues. Version 0.1 has no token-rotation endpoint; a genuinely lost or revoked identity requires an operator-controlled lab reset or database repair before enrollment can be recreated.
- Growing spool: verify TLS/network reachability and API batch limits. At its configured maximum, the spool drops the oldest complete pending batch, records the loss in health telemetry, and emits a warning. The bound protects the endpoint disk; it cannot guarantee lossless collection through an outage longer than the configured capacity.
- No Sysmon events: verify the channel exists, the service account can read it, and the bookmark is valid.

## Rule load failures

Run the CLI validator and inspect the exact file/condition error. The active ruleset remains unchanged after a failed atomic reload. Fix or remove the invalid file; never bypass validation for a demo.

## Retention

The configured retention period is enforced by the maintenance purge endpoint/CLI. Purge uses a cutoff, defaults to preview mode, requires `--execute` for deletion, removes dependent evidence consistently, and reports counts. Schedule it externally for long-running labs.
