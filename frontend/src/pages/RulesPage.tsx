import { useMemo, useState } from 'react';
import { api } from '../api/client';
import { Icon } from '../components/Icon';
import { MetricCard, PageHeader, TechniqueTag } from '../components/Page';
import { EmptyState, ErrorState, LoadingState, SeverityBadge, StatusPill } from '../components/Status';
import { useApiQuery } from '../hooks/useApiQuery';
import { formatDateTime, titleCase } from '../utils/format';

export default function RulesPage() {
  const query = useApiQuery(api.rules);
  const [search, setSearch] = useState('');
  const [source, setSource] = useState('all');
  const [enabled, setEnabled] = useState('all');

  const rules = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (query.data ?? [])
      .filter((rule) => source === 'all' || rule.source === source)
      .filter((rule) => enabled === 'all' || rule.enabled === (enabled === 'enabled'))
      .filter((rule) => !needle || [rule.title, rule.id, rule.description, ...rule.techniques].join(' ').toLowerCase().includes(needle))
      .sort((left, right) => left.title.localeCompare(right.title));
  }, [query.data, search, source, enabled]);
  const sources = [...new Set((query.data ?? []).map((rule) => rule.source))].sort();
  const techniqueCount = new Set((query.data ?? []).flatMap((rule) => rule.techniques)).size;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Detection engineering"
        title="Rule explorer"
        description="Inspect the deterministic Sigma subset and stateful correlations that turn normalized telemetry into evidence-backed alerts."
        actions={<button className="button button--secondary" onClick={query.reload} type="button"><Icon name="refresh" size={16} /> Refresh</button>}
      />

      <section className="metric-grid metric-grid--compact" aria-label="Rule metrics">
        <MetricCard detail="Loaded from versioned definitions" icon="rules" label="Detection rules" value={query.data?.length ?? 0} />
        <MetricCard detail="Active in event evaluation" icon="check" label="Enabled" tone="accent" value={query.data?.filter((rule) => rule.enabled).length ?? 0} />
        <MetricCard detail="Unique mapped techniques" icon="attack" label="ATT&CK mappings" tone="warning" value={techniqueCount} />
      </section>

      <div className="filter-bar" role="search">
        <label className="search-field">
          <span className="sr-only">Search detection rules</span>
          <Icon name="search" size={17} />
          <input onChange={(event) => setSearch(event.target.value)} placeholder="Search rule, ID, or technique" type="search" value={search} />
        </label>
        <label className="select-field"><span>Engine</span><select onChange={(event) => setSource(event.target.value)} value={source}><option value="all">All engines</option>{sources.map((item) => <option key={item} value={item}>{titleCase(item)}</option>)}</select></label>
        <label className="select-field"><span>State</span><select onChange={(event) => setEnabled(event.target.value)} value={enabled}><option value="all">Any state</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
        <span className="filter-count">{rules.length} of {query.data?.length ?? 0}</span>
      </div>

      {query.error ? <ErrorState error={query.error} onRetry={query.reload} /> : query.loading ? (
        <LoadingState label="Loading detection rules" />
      ) : rules.length ? (
        <section className="rule-grid" aria-label="Detection rules">
          {rules.map((rule) => (
            <article className="rule-card" key={rule.id}>
              <div className="rule-card__top">
                <span className="rule-card__engine"><Icon name={rule.source === 'sigma' ? 'rules' : 'graph'} size={16} /> {titleCase(rule.source)}</span>
                <StatusPill value={rule.enabled ? rule.status || 'enabled' : 'disabled'} />
              </div>
              <div className="rule-card__heading">
                <div><span className="mono-label">{rule.id}</span><h2>{rule.title}</h2></div>
                <SeverityBadge severity={rule.severity} compact />
              </div>
              <p>{rule.description}</p>
              <div className="tag-row">
                {rule.techniques.length ? rule.techniques.map((id) => <TechniqueTag id={id} key={id} />) : <span className="muted">No ATT&CK mapping</span>}
              </div>
              <details className="rule-card__details">
                <summary>Engineering details <Icon name="chevron" size={15} /></summary>
                <div>
                  <dl className="summary-grid summary-grid--rule">
                    <div><dt>Version</dt><dd>{rule.version || 'Unversioned'}</dd></div>
                    <div><dt>Updated</dt><dd>{rule.updatedAt ? formatDateTime(rule.updatedAt) : 'Not reported'}</dd></div>
                    <div><dt>Log sources</dt><dd>{rule.logSources.length ? rule.logSources.join(', ') : 'Normalized events'}</dd></div>
                    <div><dt>Confidence</dt><dd>{rule.confidence === undefined ? 'Rule-defined' : `${rule.confidence <= 1 ? Math.round(rule.confidence * 100) : Math.round(rule.confidence)}%`}</dd></div>
                  </dl>
                  <h3>False-positive considerations</h3>
                  {rule.falsePositives.length ? <ul className="plain-list">{rule.falsePositives.map((item) => <li key={item}>{item}</li>)}</ul> : <p className="muted">None documented.</p>}
                  <h3>Investigation guidance</h3>
                  {rule.guidance.length ? <ol className="guidance-list">{rule.guidance.map((item) => <li key={item}>{item}</li>)}</ol> : <p className="muted">No rule-specific guidance supplied.</p>}
                </div>
              </details>
            </article>
          ))}
        </section>
      ) : (
        <EmptyState title={query.data?.length ? 'No rules match these filters' : 'No rules loaded'} message={query.data?.length ? 'Clear a filter or broaden the search.' : 'Detection definitions will appear after the backend loads its rule catalog.'} icon="search" />
      )}
    </div>
  );
}
