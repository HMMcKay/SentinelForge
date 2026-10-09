import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { Icon } from '../components/Icon';
import { PageHeader, TechniqueTag } from '../components/Page';
import { EmptyState, ErrorState, InlineNotice, LoadingState, SeverityBadge } from '../components/Status';
import { useApiQuery } from '../hooks/useApiQuery';
import { TimelineCanvas } from '../timeline/TimelineCanvas';
import { clusterTimeline, filterTimeline, findAlertNode, graphFacets, mergeAlerts } from '../timeline/graph';
import type { TimelineFilters, TimelineNode } from '../types';
import { formatDateTime, formatTime, titleCase } from '../utils/format';

const emptyFilters: TimelineFilters = {
  host: '',
  rule: '',
  technique: '',
  severity: '',
  scenario: '',
  search: '',
};

function NodeInspector({
  node,
  graphEdges,
  onClose,
  onFocusEvidence,
}: {
  node?: TimelineNode;
  graphEdges: Array<{ source: string; target: string; type: string }>;
  onClose: () => void;
  onFocusEvidence: () => void;
}) {
  if (!node) {
    return (
      <aside className="graph-inspector graph-inspector--empty" aria-label="Graph node inspector">
        <span className="graph-inspector__glyph"><Icon name="graph" size={26} /></span>
        <h2>Inspect the evidence chain</h2>
        <p>Select a node to review normalized fields and its relationships.</p>
        <div className="inspector-tip"><Icon name="info" size={16} /><span>Alert nodes highlight every matched evidence event.</span></div>
      </aside>
    );
  }
  const relationships = graphEdges.filter((edge) => edge.source === node.id || edge.target === node.id);
  const detailFields = Object.entries(node.details)
    .filter(([key, value]) => !['id', 'label', 'type', 'severity', 'techniques'].includes(key) && value !== undefined && value !== null)
    .slice(0, 18);

  return (
    <aside className="graph-inspector" aria-label={`Details for ${node.label}`}>
      <div className="graph-inspector__header">
        <span className={`node-type-icon node-type-icon--${node.type}`}><Icon name={node.type === 'alert' ? 'alert' : node.type === 'process' ? 'activity' : node.type === 'cluster' ? 'database' : 'graph'} size={19} /></span>
        <div><span>{titleCase(node.type)} node</span><h2>{node.label}</h2></div>
        <button className="icon-button" aria-label="Close node details" onClick={onClose} type="button"><Icon name="close" size={18} /></button>
      </div>
      <div className="graph-inspector__scroll">
        <div className="graph-inspector__badges"><SeverityBadge severity={node.severity} compact />{node.host ? <span className="host-badge"><Icon name="host" size={13} /> {node.host}</span> : null}</div>
        <dl className="field-grid field-grid--stacked">
          <div><dt>Node ID</dt><dd><code>{node.id}</code></dd></div>
          {node.timestamp ? <div><dt>Event time</dt><dd>{formatDateTime(node.timestamp)}</dd></div> : null}
          {node.ruleId ? <div><dt>Detection rule</dt><dd><code>{node.ruleId}</code></dd></div> : null}
          {node.scenarioRunId ? <div><dt>Scenario run</dt><dd><code>{node.scenarioRunId}</code></dd></div> : null}
          {node.memberIds.length ? <div><dt>Cluster members</dt><dd>{node.memberIds.length} retained IDs</dd></div> : null}
          <div><dt>Relationships</dt><dd>{relationships.length}</dd></div>
        </dl>
        {node.techniques.length ? <section className="graph-inspector__section"><h3>ATT&amp;CK mapping</h3><div className="tag-row">{node.techniques.map((id) => <TechniqueTag id={id} key={id} />)}</div></section> : null}
        {node.type === 'alert' ? (
          <section className="graph-inspector__section">
            <h3>Matched evidence</h3>
            <p>{node.evidenceIds.length} evidence reference{node.evidenceIds.length === 1 ? '' : 's'} are attached to this alert.</p>
            <button className="button button--secondary button--small" onClick={onFocusEvidence} type="button"><Icon name="spark" size={15} /> Highlight chain</button>
          </section>
        ) : null}
        {detailFields.length ? (
          <section className="graph-inspector__section">
            <h3>Normalized fields</h3>
            <dl className="field-grid field-grid--stacked">
              {detailFields.map(([key, value]) => (
                <div key={key}><dt>{titleCase(key)}</dt><dd>{typeof value === 'object' ? <code>{JSON.stringify(value)}</code> : String(value)}</dd></div>
              ))}
            </dl>
          </section>
        ) : null}
        {relationships.length ? (
          <section className="graph-inspector__section">
            <h3>Edges</h3>
            <ul className="relationship-list">
              {relationships.slice(0, 12).map((edge, index) => (
                <li key={`${edge.source}-${edge.target}-${index}`}><span className={`edge-swatch edge-swatch--${edge.type}`} /> <strong>{titleCase(edge.type)}</strong><code>{edge.source === node.id ? edge.target : edge.source}</code></li>
              ))}
            </ul>
          </section>
        ) : null}
      </div>
    </aside>
  );
}

function GraphLegend() {
  return (
    <div className="graph-legend" aria-label="Graph legend">
      <span><i className="legend-node legend-node--process" />Process</span>
      <span><i className="legend-node legend-node--network" />Network</span>
      <span><i className="legend-node legend-node--file" />File</span>
      <span><i className="legend-node legend-node--registry" />Registry</span>
      <span><i className="legend-node legend-node--alert" />Alert</span>
      <span><i className="legend-edge legend-edge--process" />Process</span>
      <span><i className="legend-edge legend-edge--correlation" />Correlation</span>
      <span><i className="legend-edge legend-edge--alert" />Evidence</span>
      <span><i className="legend-edge legend-edge--scenario" />Scenario</span>
    </div>
  );
}

export default function TimelinePage() {
  const timeline = useApiQuery(api.timeline);
  const alerts = useApiQuery(api.alerts);
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedAlert = searchParams.get('alert') || '';
  const [filters, setFilters] = useState<TimelineFilters>(emptyFilters);
  const [clustered, setClustered] = useState(true);
  const [selectedId, setSelectedId] = useState<string>();
  const [focusedAlertId, setFocusedAlertId] = useState(requestedAlert);
  const [replayEnabled, setReplayEnabled] = useState(false);
  const [replayPlaying, setReplayPlaying] = useState(false);
  const [replayIndex, setReplayIndex] = useState(0);

  const merged = useMemo(() => mergeAlerts(timeline.data ?? { nodes: [], edges: [] }, alerts.data ?? []), [timeline.data, alerts.data]);
  const facets = useMemo(() => graphFacets(merged), [merged]);
  const filtered = useMemo(() => filterTimeline(merged, filters), [merged, filters]);
  const displayGraph = useMemo(() => clusterTimeline(filtered, clustered), [filtered, clustered]);
  const selected = displayGraph.nodes.find((node) => node.id === selectedId);
  const focusAlertNode = focusedAlertId ? findAlertNode(merged, focusedAlertId) : undefined;
  const evidenceIds = focusAlertNode?.evidenceIds ?? [];
  const timelinePoints = useMemo(() => [...new Set(displayGraph.nodes
    .map((node) => node.timestamp)
    .filter((timestamp): timestamp is string => typeof timestamp === 'string' && Number.isFinite(new Date(timestamp).getTime())))]
    .sort((left, right) => new Date(left).getTime() - new Date(right).getTime()), [displayGraph.nodes]);
  const visibleUntil = replayEnabled ? timelinePoints[replayIndex] : undefined;
  const filtersActive = Object.values(filters).some(Boolean);

  useEffect(() => {
    if (!requestedAlert) return;
    const node = findAlertNode(displayGraph, requestedAlert) ?? findAlertNode(merged, requestedAlert);
    if (node) {
      setSelectedId(node.id);
      setFocusedAlertId(requestedAlert);
    }
  }, [displayGraph, merged, requestedAlert]);

  useEffect(() => {
    if (selectedId && !displayGraph.nodes.some((node) => node.id === selectedId)) setSelectedId(undefined);
  }, [displayGraph.nodes, selectedId]);

  useEffect(() => {
    if (!replayPlaying || !timelinePoints.length) return undefined;
    const timer = window.setInterval(() => {
      setReplayIndex((current) => {
        if (current >= timelinePoints.length - 1) {
          setReplayPlaying(false);
          return current;
        }
        return current + 1;
      });
    }, 700);
    return () => window.clearInterval(timer);
  }, [replayPlaying, timelinePoints.length]);

  const updateFilter = (name: keyof TimelineFilters, value: string) => setFilters((current) => ({ ...current, [name]: value }));
  const selectNode = (node?: TimelineNode) => {
    setSelectedId(node?.id);
    if (node?.type === 'alert') {
      const alertId = String(node.details.alertId || node.memberIds[0] || node.id.replace(/^alert:/, ''));
      setFocusedAlertId(alertId);
      const next = new URLSearchParams(searchParams);
      next.set('alert', alertId);
      setSearchParams(next, { replace: true });
    }
  };
  const clearEvidence = () => {
    setFocusedAlertId('');
    const next = new URLSearchParams(searchParams);
    next.delete('alert');
    setSearchParams(next, { replace: true });
  };
  const toggleReplay = () => {
    if (replayEnabled) {
      setReplayEnabled(false);
      setReplayPlaying(false);
    } else {
      setReplayIndex(0);
      setReplayEnabled(true);
    }
  };
  const reload = () => { timeline.reload(); alerts.reload(); };

  return (
    <div className="page-stack timeline-page">
      <PageHeader
        eyebrow="Forensic investigation"
        title="Activity timeline"
        description="Traverse process lineage, behavior, correlations, scenario context, and the exact evidence behind each alert."
        actions={<button className="button button--secondary" onClick={reload} type="button"><Icon name="refresh" size={16} /> Refresh graph</button>}
      />

      <div className="timeline-filter-panel">
        <div className="timeline-filter-panel__search"><Icon name="search" size={17} /><input aria-label="Search timeline" onChange={(event) => updateFilter('search', event.target.value)} placeholder="Search nodes and normalized fields" type="search" value={filters.search} /></div>
        <div className="timeline-filter-grid">
          <label><span>Host</span><select onChange={(event) => updateFilter('host', event.target.value)} value={filters.host}><option value="">All hosts</option>{facets.hosts.map((value) => <option key={value}>{value}</option>)}</select></label>
          <label><span>Rule</span><select onChange={(event) => updateFilter('rule', event.target.value)} value={filters.rule}><option value="">All rules</option>{facets.rules.map((value) => <option key={value}>{value}</option>)}</select></label>
          <label><span>Technique</span><select onChange={(event) => updateFilter('technique', event.target.value)} value={filters.technique}><option value="">All techniques</option>{facets.techniques.map((value) => <option key={value}>{value}</option>)}</select></label>
          <label><span>Severity</span><select onChange={(event) => updateFilter('severity', event.target.value)} value={filters.severity}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></label>
          <label><span>Scenario</span><select onChange={(event) => updateFilter('scenario', event.target.value)} value={filters.scenario}><option value="">All scenarios</option>{facets.scenarios.map((value) => <option key={value}>{value}</option>)}</select></label>
        </div>
        <div className="timeline-filter-panel__footer">
          <span><Icon name="filter" size={15} /> {displayGraph.nodes.length} nodes · {displayGraph.edges.length} edges</span>
          <label className="toggle"><input checked={clustered} onChange={(event) => setClustered(event.target.checked)} type="checkbox" /><span />Cluster large graphs</label>
          {filtersActive ? <button className="text-button" onClick={() => setFilters(emptyFilters)} type="button">Clear filters</button> : null}
        </div>
      </div>

      {focusedAlertId && evidenceIds.length ? (
        <InlineNotice tone="warning">
          <div className="evidence-focus-notice"><span><strong>Evidence focus active</strong><p>{evidenceIds.length} matched event{evidenceIds.length === 1 ? '' : 's'} highlighted for alert {focusedAlertId}.</p></span><button className="text-button" onClick={clearEvidence} type="button">Clear focus</button></div>
        </InlineNotice>
      ) : null}
      {alerts.error ? <InlineNotice>Alert enrichment is unavailable; the base event graph can still be explored. {alerts.error.message}</InlineNotice> : null}
      {timeline.data?.truncated ? <InlineNotice tone="warning">The API truncated this timeline response. Tighten the time window or filters before drawing conclusions.</InlineNotice> : null}

      {timeline.error ? <ErrorState error={timeline.error} onRetry={timeline.reload} title="Unable to load the forensic graph" /> : timeline.loading ? (
        <LoadingState label="Building the forensic graph" />
      ) : !displayGraph.nodes.length ? (
        <EmptyState title={merged.nodes.length ? 'No nodes match these filters' : 'No telemetry to graph'} message={merged.nodes.length ? 'Clear filters or choose a different host, rule, or technique.' : 'Seed demo data or ingest Windows telemetry to build an evidence graph.'} icon="graph" />
      ) : (
        <>
          <div className="replay-bar">
            <button className={`button button--small ${replayEnabled ? 'button--primary' : 'button--secondary'}`} onClick={toggleReplay} type="button"><Icon name="clock" size={15} /> Replay {replayEnabled ? 'on' : 'off'}</button>
            <button aria-label={replayPlaying ? 'Pause replay' : 'Play replay'} className="icon-button" disabled={!replayEnabled || timelinePoints.length < 2} onClick={() => setReplayPlaying((value) => !value)} type="button"><Icon name={replayPlaying ? 'pause' : 'play'} size={17} /></button>
            <input aria-label="Replay position" disabled={!replayEnabled || timelinePoints.length < 2} max={Math.max(timelinePoints.length - 1, 0)} min="0" onChange={(event) => setReplayIndex(Number(event.target.value))} type="range" value={Math.min(replayIndex, Math.max(timelinePoints.length - 1, 0))} />
            <time>{replayEnabled && visibleUntil ? formatDateTime(visibleUntil) : 'All observed activity'}</time>
            {replayEnabled ? <span>{Math.min(replayIndex + 1, timelinePoints.length)} / {timelinePoints.length}</span> : null}
          </div>

          <section className="graph-workspace" aria-label="Forensic graph workspace">
            <div className="graph-main">
              <TimelineCanvas evidenceIds={evidenceIds} graph={displayGraph} onSelect={selectNode} selectedId={selectedId} visibleUntil={visibleUntil} />
              <GraphLegend />
            </div>
            <NodeInspector graphEdges={displayGraph.edges} node={selected} onClose={() => setSelectedId(undefined)} onFocusEvidence={() => {
              if (!selected || selected.type !== 'alert') return;
              const alertId = String(selected.details.alertId || selected.memberIds[0] || selected.id.replace(/^alert:/, ''));
              setFocusedAlertId(alertId);
            }} />
          </section>

          <details className="accessible-graph-list">
            <summary>Accessible event list ({displayGraph.nodes.length} nodes)</summary>
            <div className="accessible-graph-list__body">
              <table><thead><tr><th>Time</th><th>Type</th><th>Label</th><th>Host</th><th>Severity</th><th>Mapping</th></tr></thead>
                <tbody>{displayGraph.nodes.slice(0, 200).map((node) => (
                  <tr key={node.id}><td>{formatTime(node.timestamp)}</td><td>{titleCase(node.type)}</td><td><button onClick={() => selectNode(node)} type="button">{node.label}</button></td><td>{node.host || '—'}</td><td>{titleCase(node.severity)}</td><td>{node.techniques.join(', ') || '—'}</td></tr>
                ))}</tbody></table>
              {displayGraph.nodes.length > 200 ? <p>Showing the first 200 nodes. Use filters to narrow the accessible list.</p> : null}
            </div>
          </details>

          {focusedAlertId ? <p className="timeline-alert-link"><Link to={`/alerts/${encodeURIComponent(focusedAlertId)}`}>Open complete alert explanation <Icon name="external" size={14} /></Link></p> : null}
        </>
      )}
    </div>
  );
}
