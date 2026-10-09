# Forensic timeline

The timeline is an evidence-navigation surface, not a generic force-directed decoration. Nodes represent processes, events, alerts, scenarios, and collapsed clusters. Edges have explicit semantics: `process_parent`, `activity`, `alert_evidence`, `correlated_with`, and `scenario_member`.

## Query and rendering

The API accepts a time window plus host, rule, ATT&CK technique, severity, and scenario filters. It caps returned records and reports when a query was truncated. Stable node and edge IDs keep the layout predictable across refreshes.

The browser supports wheel/pinch zoom, pan, fit-to-view, node inspection, filters, and replay by event time. Selecting an alert emphasizes its evidence chain and de-emphasizes unrelated nodes. Large sibling sets are collapsed into deterministic clusters that can be inspected or expanded without losing the original count.

## Interpretation

A process edge means reported lineage; it does not prove an uncompromised kernel attested to the relationship. A correlation edge means SentinelForge linked events under a declared rule. A scenario edge means the event carried or was associated with a scenario run identifier. The graph must never infer these relationships solely from visual proximity.

## Performance boundary

The frontend avoids rendering an unbounded history. Narrow filters before investigating a long time range. The current architecture is appropriate for a lab-scale event set; a graph database and server-side traversal planner are not part of this release.
