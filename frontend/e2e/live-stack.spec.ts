import { expect, test } from '@playwright/test';

test.describe('live Compose stack', () => {
  test.skip(!process.env.PLAYWRIGHT_BASE_URL, 'Runs only against an externally started and seeded stack.');

  test('serves seeded operational data and a real forensic graph', async ({ page }) => {
    const consoleProblems: string[] = [];
    page.on('console', (message) => {
      if (message.type() === 'error' || message.type() === 'warning') consoleProblems.push(message.text());
    });
    const response = await page.goto('/');
    expect(response?.headers()['content-security-policy']).toContain("default-src 'self'");
    expect(response?.headers()['x-content-type-options']).toBe('nosniff');
    expect(response?.headers()['x-frame-options']).toBe('DENY');
    await expect(page.getByRole('heading', { name: 'SOC overview' })).toBeVisible();
    await expect(page.getByText('Unable to load data')).toHaveCount(0);
    const eventMetric = page.locator('.metric-card').filter({ hasText: 'Observed events' });
    await expect(eventMetric).toBeVisible();
    await expect(eventMetric.locator('strong')).not.toHaveText('0');
    const sensorMetric = page.locator('.metric-card').filter({ hasText: 'Healthy sensors' });
    await expect(sensorMetric.locator('strong')).toHaveText('1/1');

    await page.getByRole('link', { name: 'Forensic timeline' }).click();
    await expect(page.getByRole('heading', { name: 'Activity timeline' })).toBeVisible();
    await expect(page.getByRole('img', { name: /Forensic graph with [1-9]\d* nodes/ })).toBeVisible();
    await expect(page.getByText(/Accessible event list \([1-9]\d* nodes\)/)).toBeVisible();
    expect(consoleProblems).toEqual([]);
  });
});
