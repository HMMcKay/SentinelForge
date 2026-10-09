# Detection authoring

Rules live in `detections/rules` and are loaded atomically. A failed file never becomes an implicitly weakened rule. Run `sentinelctl rules validate /rules` from the CLI container before committing changes.

## Supported subset

The engine supports a deliberate subset: a `logsource`, one or more named selection maps, scalar or list equality, allowlisted string modifiers such as `contains`, `startswith`, and `endswith`, boolean `and`/`or`/`not` over selections, rule level, and ATT&CK tags. Field names target the normalized schema, not raw Sysmon labels.

Unsupported features—including arbitrary backend pipelines, wildcards in field names, unbounded regular expressions, `near`, and Sigma aggregation syntax—are validation errors. Do not rewrite an unsupported condition into a broader approximation.

## Rule review checklist

1. State the behavior, not a product-specific signature.
2. Use normalized fields and constrain the event type first.
3. Include a positive fixture and a plausible near miss.
4. Document ATT&CK mapping, likely false positives, evidence, and investigation guidance.
5. Prefer multiple meaningful conditions to long brittle command-line fragments.
6. Verify any change against the entire deterministic regression corpus.

## Stateful correlations

Correlations define a time window, grouping keys, prerequisite rule/event stages, a threshold or ordered sequence, and a deduplication interval. Alert explanations list the satisfied stages, group values, time span, and event identifiers. State is reconstructed from durable events, so an API restart does not silently erase the investigation record.
