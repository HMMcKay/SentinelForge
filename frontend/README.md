# SentinelForge frontend

The frontend is a React and TypeScript SOC workbench served as static assets by an unprivileged Nginx container. It intentionally does not embed sample findings or silently fall back to mock data: empty and unavailable API states remain visible, while demo data is created through the backend's deterministic seed endpoint.

## Local development

```text
npm ci
npm run dev
```

Vite listens on `http://localhost:5173` and proxies `/health` and `/api` to `VITE_DEV_BACKEND_URL` (`http://localhost:8000` by default). Copy `.env.example` to `.env.local` only when the backend lives elsewhere.

Available checks:

```text
npm run lint
npm test
npm run build
npm run test:e2e
```

Without `PLAYWRIGHT_BASE_URL`, Playwright starts the built preview at `http://127.0.0.1:4173`; four focused flows intercept the API with deterministic contract fixtures and do not claim backend coverage. When `PLAYWRIGHT_BASE_URL` points at a seeded Compose deployment, the same suite also runs the separate zero-mock `live-stack.spec.ts` check against PostgreSQL, FastAPI, and Nginx.

## Runtime container

The `runtime` stage listens on port `8080` and exposes `GET /healthz` as a frontend-only healthcheck. Nginx proxies the API and WebSocket feed to the Compose service named `backend` on port `8000`. The `test` stage is available to Compose-based CI.

The mutation UI requires an admin key for demo seeding and scenario runs. The value is held only in component memory, sent in the `X-Admin-Key` header over same-origin requests, and never persisted, placed in a URL, logged, or included in the bundle.

## Timeline behavior

The forensic timeline uses Cytoscape for pan, zoom, selection, and large-graph rendering. Filtering can be applied by host, rule, technique, severity, scenario, or normalized-field search. Alert nodes retain their evidence context through filtering. When an event graph exceeds the local safety threshold, low-level events from the same host, category, and five-minute window are collapsed into inspectable cluster nodes; original IDs remain attached for evidence highlighting. Replay changes graph visibility without re-running layout on each frame.

The graph also has an accessible tabular representation, keyboard zoom shortcuts (`+`, `-`, `0`), explicit loading/error/empty states, and reduced-motion support.
