import { useMemo, useState } from 'react';
import { api } from '../api/client';
import { Icon } from '../components/Icon';
import { MetricCard, PageHeader } from '../components/Page';
import { EmptyState, ErrorState, LoadingState } from '../components/Status';
import { useApiQuery } from '../hooks/useApiQuery';
import type { CoverageItem } from '../types';

function TechniqueCell({ item }: { item: CoverageItem }) {
  return (
    <article className={`coverage-cell${item.covered ? ' coverage-cell--covered' : ''}`}>
      <div><strong>{item.techniqueId}</strong><span>{item.covered ? 'Covered' : 'Gap'}</span></div>
      <h3>{item.name}</h3>
      <p>{item.ruleCount} rule{item.ruleCount === 1 ? '' : 's'} · {item.alertCount} alert{item.alertCount === 1 ? '' : 's'}</p>
    </article>
  );
}

export default function AttackPage() {
  const query = useApiQuery(api.coverage);
  const [search, setSearch] = useState('');
  const [view, setView] = useState<'all' | 'covered' | 'gaps'>('all');
  const items = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (query.data?.items ?? [])
      .filter((item) => view === 'all' || (view === 'covered' ? item.covered : !item.covered))
      .filter((item) => !needle || [item.techniqueId, item.name, item.tactic].join(' ').toLowerCase().includes(needle));
  }, [query.data, search, view]);
  const tactics = useMemo(() => {
    const groups = new Map<string, CoverageItem[]>();
    items.forEach((item) => groups.set(item.tactic, [...(groups.get(item.tactic) ?? []), item]));
    return [...groups.entries()].sort(([left], [right]) => left.localeCompare(right));
  }, [items]);
  const percent = query.data?.totalTechniques ? Math.round((query.data.coveredTechniques / query.data.totalTechniques) * 100) : 0;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Knowledge mapping"
        title="ATT&CK coverage"
        description="Trace implemented detections to the adversary techniques they observe; uncovered entries are explicit engineering gaps, not implied coverage."
        actions={<button className="button button--secondary" onClick={query.reload} type="button"><Icon name="refresh" size={16} /> Refresh</button>}
      />

      <section className="metric-grid metric-grid--compact" aria-label="Coverage metrics">
        <MetricCard detail="Of catalog techniques represented" icon="attack" label="Technique coverage" tone="accent" value={`${percent}%`} />
        <MetricCard detail={`${query.data?.totalTechniques ?? 0} in the local catalog`} icon="check" label="Covered techniques" value={query.data?.coveredTechniques ?? 0} />
        <MetricCard detail="Versioned detection definitions" icon="rules" label="Mapped rules" tone="warning" value={query.data?.ruleCount ?? 0} />
      </section>

      <div className="coverage-progress" aria-label={`${percent}% technique coverage`}>
        <div><span>Implemented</span><strong>{query.data?.coveredTechniques ?? 0} / {query.data?.totalTechniques ?? 0}</strong></div>
        <div className="progress progress--large"><span className="progress__fill" style={{ width: `${percent}%` }} /></div>
        <p>Coverage means at least one mapped local detection. It does not claim prevention, sensor parity, or full ATT&CK validation.</p>
      </div>

      <div className="filter-bar" role="search">
        <label className="search-field"><span className="sr-only">Search ATT&amp;CK coverage</span><Icon name="search" size={17} /><input onChange={(event) => setSearch(event.target.value)} placeholder="Search technique or tactic" type="search" value={search} /></label>
        <div className="segmented-control" aria-label="Coverage status">
          <button aria-pressed={view === 'all'} onClick={() => setView('all')} type="button">All</button>
          <button aria-pressed={view === 'covered'} onClick={() => setView('covered')} type="button">Covered</button>
          <button aria-pressed={view === 'gaps'} onClick={() => setView('gaps')} type="button">Gaps</button>
        </div>
        <span className="filter-count">{items.length} techniques</span>
      </div>

      {query.error ? <ErrorState error={query.error} onRetry={query.reload} /> : query.loading ? (
        <LoadingState label="Loading ATT&CK mappings" />
      ) : tactics.length ? (
        <section className="tactic-list" aria-label="ATT&CK tactics and techniques">
          {tactics.map(([tactic, techniques]) => (
            <section className="tactic-row" key={tactic}>
              <header><span className="eyebrow">Tactic</span><h2>{tactic}</h2><p>{techniques.filter((item) => item.covered).length}/{techniques.length} shown covered</p></header>
              <div className="tactic-row__techniques">{techniques.map((item) => <TechniqueCell item={item} key={item.techniqueId} />)}</div>
            </section>
          ))}
        </section>
      ) : <EmptyState title={query.data?.items.length ? 'No techniques match these filters' : 'No ATT&CK mappings loaded'} message={query.data?.items.length ? 'Broaden the search or change the coverage filter.' : 'The coverage endpoint returned an empty technique catalog.'} icon="search" />}
    </div>
  );
}
