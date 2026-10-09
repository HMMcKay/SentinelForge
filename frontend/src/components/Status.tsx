import type { Severity } from '../types';
import { titleCase } from '../utils/format';
import { Icon } from './Icon';

export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  return (
    <span className={`severity severity--${severity}${compact ? ' severity--compact' : ''}`}>
      <span className="severity__dot" aria-hidden="true" />
      {titleCase(severity)}
    </span>
  );
}

export function StatusPill({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const tone = ['healthy', 'online', 'connected', 'open', 'completed', 'stable'].includes(normalized)
    ? 'positive'
    : ['failed', 'offline', 'error', 'disabled'].includes(normalized)
      ? 'negative'
      : ['running', 'queued', 'connecting', 'testing'].includes(normalized)
        ? 'active'
        : 'neutral';
  return <span className={`status-pill status-pill--${tone}`}>{titleCase(value)}</span>;
}

export function LoadingState({ label = 'Loading data' }: { label?: string }) {
  return (
    <div className="state-panel" role="status">
      <span className="spinner" aria-hidden="true" />
      <strong>{label}</strong>
      <span>Waiting for the SentinelForge API.</span>
    </div>
  );
}

export function EmptyState({
  title,
  message,
  icon = 'info',
  action,
}: {
  title: string;
  message: string;
  icon?: 'info' | 'search' | 'graph' | 'alert';
  action?: React.ReactNode;
}) {
  return (
    <div className="state-panel state-panel--empty">
      <span className="state-panel__icon"><Icon name={icon} size={24} /></span>
      <strong>{title}</strong>
      <span>{message}</span>
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry, title = 'Unable to load data' }: { error: Error; onRetry: () => void; title?: string }) {
  return (
    <div className="state-panel state-panel--error" role="alert">
      <span className="state-panel__icon"><Icon name="warning" size={24} /></span>
      <strong>{title}</strong>
      <span>{error.message}</span>
      <button className="button button--secondary button--small" onClick={onRetry} type="button">
        <Icon name="refresh" size={15} /> Retry
      </button>
    </div>
  );
}

export function InlineNotice({
  tone = 'info',
  children,
}: {
  tone?: 'info' | 'warning' | 'success' | 'danger';
  children: React.ReactNode;
}) {
  return (
    <div className={`notice notice--${tone}`} role={tone === 'danger' ? 'alert' : 'status'}>
      <Icon name={tone === 'success' ? 'check' : tone === 'info' ? 'info' : 'warning'} size={18} />
      <div>{children}</div>
    </div>
  );
}
