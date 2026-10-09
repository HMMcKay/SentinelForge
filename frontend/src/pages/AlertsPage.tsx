import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import { Icon } from '../components/Icon';
import { PageHeader, TechniqueTag } from '../components/Page';
import { EmptyState, ErrorState, LoadingState, SeverityBadge, StatusPill } from '../components/Status';
import { useApiQuery } from '../hooks/useApiQuery';
import type { Alert, AlertEvidence } from '../types';
import { compactId, formatDateTime, relativeTime, severityRank, titleCase } from '../utils/format';

function EvidenceCard({ evidence, index }: { evidence: AlertEvidence; index: number }) {
  const fields = Object.entries(evidence.fields).filter(([, value]) => value !== null && value !== undefined);
  return (
    <details className="evidence-card" open={index === 0}>
      <summary>
        <span className="evidence-card__index">{String(index + 1).padStart(2, '0')}</span>
        <span>
          <strong>{evidence.summary}</strong>
          <small>{evidence.timestamp ? formatDateTime(evidence.timestamp) : `Event ${compactId(evidence.eventId)}`}</small>
        </span>
        <Icon name="chevron" size={16} />
      </summary>
      <div className="evidence-card__body">
        <dl className="field-grid">
          <div><dt>Event ID</dt><dd><code>{evidence.eventId}</code></dd></div>
          {fields.map(([key, value]) => (
            <div key={key}>
              <dt>{titleCase(key)}</dt>
              <dd>{typeof value === 'object' ? <code>{JSON.stringify(value)}</code> : String(value)}</dd>
            </div>
          ))}
        </dl>
      </div>
    </details>
  );
}

function AlertInspector({ id, fallback }: { id: string; fallback?: Alert }) {
  const navigate = useNavigate();
  const loader = useMemo(() => (signal: AbortSignal) => api.alert(id, signal), [id]);
  const detail = useApiQuery(loader);
  const alert = detail.data ?? fallback;

  return (
    <aside className="inspector" aria-label="Alert details">
      <div className="inspector__header">
        <div>
          <span className="eyebrow">Alert investigation</span>
          <h2>{alert?.title ?? 'Loading alert'}</h2>
        </div>
        <button className="icon-button" aria-label="Close alert details" onClick={() => navigate('/alerts')} type="button">
          <Icon name="close" />
        </button>
      </div>
      {detail.error && !alert ? <ErrorState error={detail.error} onRetry={detail.reload} /> : detail.loading && !alert ? (
        <LoadingState label="Loading alert evidence" />
      ) : alert ? (
        <div className="inspector__scroll">
          {detail.error ? (
            <div className="inline-error">Fresh detail could not be loaded; showing list data. <button onClick={detail.reload} type="button">Retry</button></div>
          ) : null}
          <div className="alert-summary">
            <div className="alert-summary__badges">
              <SeverityBadge severity={alert.severity} />
              <StatusPill value={alert.status} />
              <span className="confidence">{alert.confidence}% confidence</span>
            </div>
            <dl className="summary-grid">
              <div><dt>Host</dt><dd>{alert.host.name}</dd></div>
              <div><dt>Detected</dt><dd>{formatDateTime(alert.createdAt)}</dd></div>
              <div><dt>Rule ID</dt><dd><code>{alert.ruleId}</code></dd></div>
              <div><dt>Evidence</dt><dd>{alert.evidence.length} matched event{alert.evidence.length === 1 ? '' : 's'}</dd></div>
            </dl>
          </div>

          <section className="inspector-section">
            <h3>Why this fired</h3>
            <p className="explanation">{alert.reason}</p>
            <div className="tag-row">{alert.techniques.map((id) => <TechniqueTag id={id} key={id} />)}</div>
          </section>

          <section className="inspector-section">
            <div className="section-heading">
              <h3>Matched evidence</h3>
              <Link className="text-link" to={`/timeline?alert=${encodeURIComponent(alert.id)}`}>
                Highlight in graph <Icon name="external" size={14} />
              </Link>
            </div>
            {alert.evidence.length ? alert.evidence.map((evidence, index) => (
              <EvidenceCard evidence={evidence} index={index} key={`${evidence.eventId}-${index}`} />
            )) : <EmptyState title="Evidence detail unavailable" message="The alert record did not include matched event references." />}
          </section>

          <section className="inspector-section">
            <h3>Investigation guidance</h3>
            {alert.guidance.length ? (
              <ol className="guidance-list">{alert.guidance.map((item) => <li key={item}>{item}</li>)}</ol>
            ) : <p className="muted">No rule-specific guidance was supplied.</p>}
          </section>

          <section className="inspector-section">
            <h3>False-positive considerations</h3>
            {alert.falsePositives.length ? (
              <ul className="plain-list">{alert.falsePositives.map((item) => <li key={item}>{item}</li>)}</ul>
            ) : <p className="muted">No known false-positive notes were supplied.</p>}
          </section>
        </div>
      ) : null}
    </aside>
  );
}

export default function AlertsPage() {
  const { alertId } = useParams();
  const navigate = useNavigate();
  const query = useApiQuery(api.alerts);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return [...(query.data ?? [])]
      .filter((alert) => severityFilter === 'all' || alert.severity === severityFilter)
      .filter((alert) => statusFilter === 'all' || alert.status === statusFilter)
      .filter((alert) => !needle || [alert.title, alert.ruleId, alert.host.name, ...alert.techniques].join(' ').toLowerCase().includes(needle))
      .sort((left, right) => severityRank(right.severity) - severityRank(left.severity) || new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime());
  }, [query.data, search, severityFilter, statusFilter]);
  const selectedFallback = query.data?.find((alert) => alert.id === alertId);
  const statuses = [...new Set((query.data ?? []).map((alert) => alert.status))].sort();

  return (
    <div className="page-stack alerts-page">
      <PageHeader
        eyebrow="Detection operations"
        title="Alert triage"
        description="Review each detection with its matched telemetry, rule context, and next investigative steps."
        actions={
          <button className="button button--secondary" onClick={query.reload} type="button">
            <Icon name="refresh" size={16} /> Refresh
          </button>
        }
      />

      <div className="filter-bar" role="search">
        <label className="search-field">
          <span className="sr-only">Search alerts</span>
          <Icon name="search" size={17} />
          <input onChange={(event) => setSearch(event.target.value)} placeholder="Search title, host, rule, or technique" type="search" value={search} />
        </label>
        <label className="select-field">
          <span>Severity</span>
          <select onChange={(event) => setSeverityFilter(event.target.value)} value={severityFilter}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
          </select>
        </label>
        <label className="select-field">
          <span>Status</span>
          <select onChange={(event) => setStatusFilter(event.target.value)} value={statusFilter}>
            <option value="all">All statuses</option>
            {statuses.map((status) => <option key={status} value={status}>{titleCase(status)}</option>)}
          </select>
        </label>
        <span className="filter-count">{filtered.length} of {query.data?.length ?? 0}</span>
      </div>

      <section className="alert-list panel" aria-label="Alert queue">
        <div className="alert-list__head" aria-hidden="true">
          <span>Detection</span><span>Host</span><span>Mapping</span><span>Detected</span><span>Severity</span><span />
        </div>
        {query.error ? <ErrorState error={query.error} onRetry={query.reload} /> : query.loading ? (
          <LoadingState label="Loading alert queue" />
        ) : filtered.length ? filtered.map((alert) => (
          <button
            className={`alert-row${alert.id === alertId ? ' alert-row--selected' : ''}`}
            key={alert.id}
            onClick={() => navigate(`/alerts/${encodeURIComponent(alert.id)}`)}
            type="button"
          >
            <span className="alert-row__title">
              <span className="alert-marker" data-severity={alert.severity} aria-hidden="true" />
              <span><strong>{alert.title}</strong><small>{alert.ruleName || alert.ruleId}</small></span>
            </span>
            <span className="alert-row__host"><Icon name="host" size={15} /> {alert.host.name}</span>
            <span className="tag-row">{alert.techniques.slice(0, 2).map((id) => <TechniqueTag id={id} key={id} />)}{alert.techniques.length > 2 ? <small>+{alert.techniques.length - 2}</small> : null}</span>
            <span>{relativeTime(alert.createdAt)}</span>
            <SeverityBadge severity={alert.severity} compact />
            <Icon name="chevron" size={16} />
          </button>
        )) : (
          <EmptyState
            title={query.data?.length ? 'No alerts match these filters' : 'No alerts detected'}
            message={query.data?.length ? 'Broaden the search or clear one of the filters.' : 'Run a safe scenario or seed demo data to exercise the detection pipeline.'}
            icon={query.data?.length ? 'search' : 'alert'}
          />
        )}
      </section>

      {alertId ? <AlertInspector fallback={selectedFallback} id={alertId} /> : null}
      {alertId ? <button className="inspector-backdrop" aria-label="Close alert details" onClick={() => navigate('/alerts')} type="button" /> : null}
    </div>
  );
}
