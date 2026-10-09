# ADR 0003: Keep the Windows sensor outside the Linux Compose stack

- Status: Accepted
- Date: 2026-07-27

## Context

The sensor must access the Windows Event Log and DPAPI. A Linux container cannot faithfully provide those host facilities, and a Windows container would make the otherwise portable Compose deployment host-specific.

## Decision

Compose runs PostgreSQL, the API, the web UI, and the on-demand CLI. Install the small .NET worker directly in the isolated Windows VM as a console process or Windows service.

## Consequences

The core demonstration works without Windows using deterministic seed data. Real Sysmon collection requires a separate, documented Windows installation step.
