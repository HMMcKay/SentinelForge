# Public project page

The public explanation is published at [hmmckay.github.io/SentinelForge](https://hmmckay.github.io/SentinelForge/).

It is a static site, separate from the operational dashboard. It explains the behavior-to-evidence workflow, component boundaries, investigation graph, engineering choices, and known limits. It cannot collect telemetry or execute a simulation.

## Source and deployment

`docs/site/` contains plain HTML, CSS, JavaScript, an inline SVG architecture diagram, and real dashboard screenshots. There are no third-party fonts, analytics, CDNs, or frontend build dependencies. All site resources use relative paths so the repository subpath works on GitHub Pages.

The screenshot originals are under `docs/assets/`; the copies under `docs/site/assets/` are deployment assets. The screenshots use deterministic synthetic data from the dated validation record, not live endpoint measurements.

`.github/workflows/pages.yml` packages only `docs/site/` and deploys it using GitHub Pages. Actions are pinned by SHA. Deployment gets `pages: write` and `id-token: write`; source checkout only gets `contents: read`.

Repository Settings → Pages must use **GitHub Actions** as its source. A push that changes the site or its workflow triggers publication. The workflow can also be run manually.

## Local review

From the repository root, use Python 3 to serve the static files:

```powershell
python -m http.server 8765 --bind 127.0.0.1 --directory docs/site
```

Open `http://127.0.0.1:8765`. Review desktop and mobile widths, all six workflow stages, screenshot enlargement, keyboard focus, and the command-copy control. Stop the server with Ctrl+C when finished.

Check source and resource invariants with:

```powershell
python scripts/check-pages.py
```

Keep claims source-backed and dated. Do not add production readiness, endpoint efficacy, benchmark, or integration claims based only on mocks or synthetic data.
