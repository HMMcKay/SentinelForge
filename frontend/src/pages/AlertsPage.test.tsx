import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { Alert } from '../types';
import AlertsPage from './AlertsPage';

const fixture: Alert = {
  id: 'alert-1',
  title: 'Encoded PowerShell execution',
  ruleId: 'SF-PS-001',
  severity: 'high',
  confidence: 94,
  status: 'open',
  createdAt: '2026-01-01T00:02:00Z',
  host: { name: 'LAB-01' },
  reason: 'PowerShell launched with an encoded command flag.',
  techniques: ['T1059.001'],
  evidence: [{ eventId: 'event-1', summary: 'Encoded command line', fields: { process_name: 'powershell.exe' } }],
  guidance: ['Decode and review the command payload.'],
  falsePositives: ['Approved automation using encoded parameters.'],
};

vi.mock('../api/client', () => ({
  api: {
    alerts: vi.fn(() => Promise.resolve([fixture])),
    alert: vi.fn(() => Promise.resolve(fixture)),
  },
}));

vi.mock('../context/LiveContext', () => ({
  useLive: () => ({ refreshToken: 0 }),
}));

describe('alert triage', () => {
  it('opens an alert and explains its evidence', async () => {
    render(
      <MemoryRouter initialEntries={['/alerts']}>
        <Routes>
          <Route element={<AlertsPage />} path="/alerts" />
          <Route element={<AlertsPage />} path="/alerts/:alertId" />
        </Routes>
      </MemoryRouter>,
    );

    const row = await screen.findByRole('button', { name: /encoded powershell execution/i });
    await userEvent.click(row);
    expect(await screen.findByRole('heading', { name: 'Encoded PowerShell execution' })).toBeVisible();
    expect(screen.getByText('Why this fired')).toBeVisible();
    expect(screen.getByText('PowerShell launched with an encoded command flag.')).toBeVisible();
    expect(screen.getByText('Matched evidence')).toBeVisible();
  });
});
