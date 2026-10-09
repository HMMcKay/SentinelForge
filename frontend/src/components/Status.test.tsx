import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ErrorState, SeverityBadge } from './Status';

describe('status components', () => {
  it('exposes severity in visible text', () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText('Critical')).toBeVisible();
  });

  it('provides an actionable retry state', async () => {
    const retry = vi.fn();
    render(<ErrorState error={new Error('API unavailable')} onRetry={retry} />);
    expect(screen.getByRole('alert')).toHaveTextContent('API unavailable');
    await userEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(retry).toHaveBeenCalledOnce();
  });
});
