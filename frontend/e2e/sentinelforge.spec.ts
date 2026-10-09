import { expect, test, type Page, type Route } from '@playwright/test';

const alert = {
  id: 'alert-1',
  title: 'Encoded PowerShell execution',
  rule_id: 'SF-PS-001',
  severity: 'high',
  confidence: 0.94,
  status: 'open',
  created_at: '2026-07-27T18:03:00Z',
  host: { name: 'LAB-01' },
  reason: 'PowerShell launched with an encoded command flag from a user-writable path.',
  techniques: ['T1059.001'],
  evidence: [{ event_id: 'event-2', summary: 'Encoded command line', timestamp: '2026-07-27T18:02:00Z', fields: { process_name: 'powershell.exe', command_line: 'powershell.exe -EncodedCommand <benign>' } }],
  guidance: ['Decode the command and verify the initiating user.', 'Review the parent process lineage.'],
  false_positives: ['Approved administrative automation.'],
};

const apiFixtures: Record<string, unknown> = {
  '/api/v1/sensors': { items: [{ id: 'sensor-1', hostname: 'LAB-01', name: 'LAB-01', status: 'healthy', last_seen: '2026-07-27T18:04:00Z', version: '0.1.0' }], total: 1 },
  '/api/v1/events': { items: [
    { id: 'event-1', event_time: '2026-07-27T18:01:00Z', category: 'process', action: 'start', host: { name: 'LAB-01' }, process: { name: 'cmd.exe', guid: 'p1' }, techniques: [] },
    { id: 'event-2', event_time: '2026-07-27T18:02:00Z', category: 'process', action: 'start', host: { name: 'LAB-01' }, process: { name: 'powershell.exe', guid: 'p2', parent_entity_id: 'p1' }, severity: 'high', techniques: ['T1059.001'] },
  ], total: 2 },
  '/api/v1/alerts': { items: [alert], total: 1 },
  '/api/v1/alerts/alert-1': alert,
  '/api/v1/rules': { items: [{ id: 'SF-PS-001', title: 'Encoded PowerShell', description: 'Detects encoded PowerShell command-line flags.', status: 'stable', severity: 'high', source: 'sigma', enabled: true, techniques: ['T1059.001'], false_positives: ['Approved automation'] }], total: 1 },
  '/api/v1/scenarios': { items: [{ id: 'encoded-powershell', name: 'Encoded PowerShell benign execution', description: 'Runs a harmless encoded expression to generate process telemetry.', technique_ids: ['T1059.001'], platform: 'Windows', safety: 'No external payloads or persistence', reversible: true, supports_dry_run: true, enabled: true, lab_mode_required: true }], total: 1 },
  '/api/v1/attack/coverage': { items: [{ technique_id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', rule_count: 1, alert_count: 1, covered: true }], summary: { covered_techniques: 1, total_techniques: 1, rule_count: 1 } },
  '/api/v1/timeline': {
    nodes: [
      { id: 'node-1', type: 'process', label: 'cmd.exe', timestamp: '2026-07-27T18:01:00Z', host: 'LAB-01', event_id: 'event-1', severity: 'informational', details: { process_guid: 'p1' } },
      { id: 'node-2', type: 'process', label: 'powershell.exe', timestamp: '2026-07-27T18:02:00Z', host: 'LAB-01', event_id: 'event-2', severity: 'high', techniques: ['T1059.001'], details: { process_guid: 'p2', command_line: 'powershell.exe -EncodedCommand <benign>' } },
    ],
    edges: [{ id: 'edge-1', source: 'node-1', target: 'node-2', type: 'process' }],
  },
};

async function mockApi(page: Page, capture?: { adminHeaders: string[]; runBodies?: unknown[] }) {
  await page.route('**/health', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 'healthy', version: '0.1.0', lab_mode: true }) }));
  await page.route('**/api/v1/**', async (route: Route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === 'POST') {
      capture?.adminHeaders.push(request.headers()['x-admin-key'] || '');
      if (path === '/api/v1/demo/seed') {
        await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ message: 'Seeded deterministic demo dataset.' }) });
        return;
      }
      if (path.endsWith('/runs')) {
        capture?.runBodies?.push(request.postDataJSON());
        await route.fulfill({ status: 202, contentType: 'application/json', body: JSON.stringify({ id: 'run-1', scenario_id: 'encoded-powershell', status: 'queued', dry_run: true }) });
        return;
      }
    }
    const fixture = apiFixtures[path];
    if (fixture) await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixture) });
    else await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ detail: 'Not found in test contract.' }) });
  });
}

test('triages an evidence-backed alert from the overview', async ({ page }) => {
  await mockApi(page);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'SOC overview' })).toBeVisible();
  await expect(page.getByText('Encoded PowerShell execution').first()).toBeVisible();
  await page.getByText('Encoded PowerShell execution').first().click();
  await expect(page.getByRole('heading', { name: 'Encoded PowerShell execution' })).toBeVisible();
  await expect(page.getByText('Why this fired')).toBeVisible();
  await expect(page.getByText('PowerShell launched with an encoded command flag from a user-writable path.')).toBeVisible();
  await expect(page.getByText('Matched evidence')).toBeVisible();
});

test('filters, inspects, and replays the forensic graph', async ({ page }) => {
  await mockApi(page);
  await page.goto('/timeline?alert=alert-1');
  await expect(page.getByRole('heading', { name: 'Activity timeline' })).toBeVisible();
  await expect(page.getByText('Evidence focus active')).toBeVisible();
  await expect(page.locator('.timeline-filter-panel__footer').getByText(/3 nodes/)).toBeVisible();
  await page.getByRole('button', { name: 'Replay off' }).click();
  await expect(page.getByRole('button', { name: 'Replay on' })).toBeVisible();
  await page.getByText(/Accessible event list/).click();
  await page.getByRole('button', { name: 'cmd.exe' }).click();
  await expect(page.getByRole('heading', { name: 'cmd.exe' })).toBeVisible();
  await page.getByLabel('Search timeline').fill('powershell');
  await expect(page.locator('.timeline-filter-panel__footer').getByText(/2 nodes/)).toBeVisible();
});

test('keeps admin credentials ephemeral and sends them only as mutation headers', async ({ page }) => {
  const capture = { adminHeaders: [] as string[] };
  await mockApi(page, capture);
  await page.goto('/scenarios');
  const seedButton = page.getByRole('button', { name: 'Seed demo' });
  await expect(seedButton).toBeDisabled();
  await page.getByLabel('Admin key').fill('local-test-key');
  await expect(seedButton).toBeEnabled();
  await seedButton.click();
  await expect(page.getByText('Demo data ready')).toBeVisible();
  expect(capture.adminHeaders).toEqual(['local-test-key']);
  expect(page.url()).not.toContain('local-test-key');
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
});

test('requires an explicit enrolled sensor target for live lab execution', async ({ page }) => {
  const capture = { adminHeaders: [] as string[], runBodies: [] as unknown[] };
  await mockApi(page, capture);
  await page.goto('/scenarios');
  await page.getByLabel('Admin key').fill('local-test-key');
  await page.getByRole('button', { name: /configure/i }).click();
  await page.getByRole('radio', { name: /execute in lab/i }).check();
  const startButton = page.getByRole('button', { name: /start lab run/i });
  await expect(startButton).toBeDisabled();
  await page.getByLabel('Target enrolled sensor').selectOption('sensor-1');
  await page.getByPlaceholder('RUN IN LAB').fill('RUN IN LAB');
  await expect(startButton).toBeEnabled();
  await startButton.click();
  await expect(page.getByText(/run queued/i)).toBeVisible();
  expect(capture.adminHeaders).toEqual(['local-test-key']);
  expect(capture.runBodies).toEqual([{ dry_run: false, sensor_id: 'sensor-1' }]);
});
