# Detection content

SentinelForge loads the YAML files in `rules/` at startup. The evaluator intentionally supports a bounded Sigma-like subset: mapping selections, case-insensitive equality, `contains`, `startswith`, `endswith`, `exists`, list values, boolean conditions, and `1/all of` wildcards. It rejects unsupported modifiers and native Sigma `timeframe` rather than silently changing their meaning.

Stateful behavior is expressed through the `sentinelforge.correlation` extension. Supported correlation types are host/group-scoped thresholds and ordered sequences with explicit windows and deduplication periods.

Run validation with:

```console
sentinelctl rules validate detections/rules
```
