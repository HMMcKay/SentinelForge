# ADR 0004: Return a bounded forensic graph and render it client-side

- Status: Accepted
- Date: 2026-07-27

## Context

Process lineage, related activity, alert evidence, and scenario membership are difficult to understand as independent tables. Returning every event would overwhelm both the API and the browser.

## Decision

The timeline endpoint returns typed nodes and edges for a bounded time/query window. The browser applies filters, evidence highlighting, replay, zoom/pan, and deterministic clustering. The API enforces result limits and exposes truncation metadata.

## Consequences

Small investigations are interactive without a graph database. Cross-host, long-retention graph analytics remain out of scope; operators must narrow the query window.
