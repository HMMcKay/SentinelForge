# Security policy

SentinelForge is a defensive lab project, but defects in its ingestion, credential handling, or simulation containment can still matter.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** flow under the repository's Security tab. That creates a private security advisory visible only to repository maintainers. Do not open a public issue for a suspected credential leak, sandbox escape, authentication bypass, or unsafe simulation behavior.

Include the affected version or commit, environment, reproduction steps, impact, and any suggested mitigation. Remove real event data, access tokens, hostnames, usernames, and other lab identifiers before attaching evidence.

There is intentionally no placeholder email address in this policy. If private vulnerability reporting is unavailable, open a public issue containing only a request that maintainers enable a private channel; do not include exploit details.

## Supported versions

Until a stable release exists, security fixes are made on the default branch. Tagged pre-1.0 versions receive fixes only when called out in their release notes.

## Scope notes

Safe reports include simulation path escape, cleanup affecting non-sandbox data, sensor-token disclosure, authentication bypass, stored script injection, SQL injection, unbounded resource use, and container privilege regressions. A rule failing to detect unrelated offensive tooling is generally a detection-quality issue, not a platform vulnerability.
