import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { Icon } from '../components/Icon';
import { MetricCard, PageHeader, Panel, TechniqueTag } from '../components/Page';
import { EmptyState, ErrorState, LoadingState, SeverityBadge, StatusPill } from '../components/Status';
import { useApiQuery } from '../hooks/useApiQuery';
import type { EventRecord, Severity } from '../types';
import { formatNumber, formatTime, relativeTime, severityRank } from '../utils/format';

function ActivityHistogram({ events }: { events: EventRecord[] }) {
  const times = events
    .map((event) => new Date(event.eventTime).getTime())
    .filter(Number.isFinite)
    .sort((a, b) => a - b);
  const bucketCount = 16;
  const start = times[0] ?? Date.now();
  const end = times[times.length - 1] ?? start;
  const span = Math.max(end - start, bucketCount);
  const buckets = Array.from({ length: bucketCount }, () => 0);
  times.forEach((time) => {
    const index = Math.min(bucketCount - 1, Math.floor(((time - start) / span) * bucketCount));
    buckets[index] = (buckets[index] ?? 0) + 1;
  });
  const max = Math.max(...buckets, 1);

  return (
    <div className="activity-chart" role="img" aria-label={`Event activity across ${bucketCount} time intervals`}>
      <div className="activity-chart__plot">
        {buckets.map((count, index) => (
          <span
            className="activity-chart__bar"
            key={index}
            style={{ height: `${Math.max(4, (count / max) * 100)}%` }}
            title={`${count} event${count === 1 ? '' : 's'}`}
          />
        ))}
      </div>
      <div className="activity-chart__axis">
        <span>{times.length ? formatTime(new Date(start).toISOString()) : 'No events'}</span>
        <span>{times.length ? formatTime(new Date(end).toISOString()) : '—'}</span>
      </div>
    </div>
  );
}

export default function OverviewPage() {
  const alerts = useApiQuery(api.alerts);
  const sensors = useApiQuery(api.sensors);
  const events = useApiQuery(api.events);
  const coverage = useApiQuery(api.coverage);
  const alertRows = [...(alerts.data ?? [])].sort((left, right) => {
    const severityDifference = severityRank(right.severity) - severityRank(left.severity);
    return severityDifference || new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime();
  });
  const openAlerts = alertRows.filter((alert) => !['closed', 'resolved'].includes(alert.status));
  const highAlerts = openAlerts.filter((alert) => ['critical', 'high'].includes(alert.severity));
  const onlineSensors = (sensors.data ?? []).filter((sensor) => ['healthy', 'active', 'online', 'connected'].includes(sensor.status));
  const eventTechniques = new Set((events.data ?? []).flatMap((event) => event.techniques));
  const isInitialLoading = [alerts, sensors, events, coverage].every((query) => query.loading);

  const reloadAll = () => {
    alerts.reload();
    sensors.reload();
    events.reload();
    coverage.reload();
  };

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Detection operations"
        title="SOC overview"
        description="A current view of lab telemetry, detection outcomes, and endpoint collection health."
        actions={
          <button className="button button--secondary" onClick={reloadAll} type="button">
            <Icon name="refresh" size={16} /> Refresh
          </button>
        }
      />

      {isInitialLoading ? <LoadingState label="Loading the operational picture" /> : null}

      <section className="metric-grid" aria-label="Operational metrics">
        <MetricCard
          detail={highAlerts.length ? `${highAlerts.length} require priority review` : 'No high-priority open alerts'}
          icon="alert"
          label="Open alerts"
          tone={highAlerts.length ? 'danger' : 'default'}
          value={formatNumber(openAlerts.length)}
        />
        <MetricCard
          detail={`${formatNumber(events.data?.length ?? 0)} in the current API window`}
          icon="activity"
          label="Observed events"
          tone="accent"
          value={formatNumber(events.data?.length ?? 0)}
        />
        <MetricCard
          detail={`${onlineSensors.length} of ${sensors.data?.length ?? 0} reporting`}
          icon="sensor"
          label="Healthy sensors"
          value={`${onlineSensors.length}/${sensors.data?.length ?? 0}`}
        />
        <MetricCard
          detail={`${coverage.data?.ruleCount ?? 0} mapped rules`}
          icon="attack"
          label="ATT&CK coverage"
          tone="warning"
          value={`${coverage.data?.coveredTechniques ?? eventTechniques.size}/${coverage.data?.totalTechniques ?? 0}`}
        />
      </section>

      <div className="dashboard-grid">
        <Panel
          className="dashboard-grid__wide"
          title="Telemetry activity"
          subtitle="Normalized events returned in the active ingestion window"
          action={<Link className="text-link" to="/timeline">Open timeline <Icon name="chevron" size={14} /></Link>}
        >
          {events.error ? <ErrorState error={events.error} onRetry={events.reload} /> : events.loading ? (
            <LoadingState label="Loading events" />
          ) : events.data?.length ? (
            <ActivityHistogram events={events.data} />
          ) : (
            <EmptyState title="No telemetry yet" message="Enroll a sensor or seed the deterministic demo dataset." icon="graph" />
          )}
        </Panel>

        <Panel
          title="Collection status"
          subtitle="Last contact from enrolled sensors"
          action={<span className="count-label">{sensors.data?.length ?? 0} total</span>}
        >
          {sensors.error ? <ErrorState error={sensors.error} onRetry={sensors.reload} /> : sensors.loading ? (
            <LoadingState label="Loading sensors" />
          ) : sensors.data?.length ? (
            <div className="sensor-list">
              {sensors.data.slice(0, 5).map((sensor) => (
                <div className="sensor-row" key={sensor.id}>
                  <span className="sensor-row__icon"><Icon name="host" size={18} /></span>
                  <div>
                    <strong>{sensor.hostname}</strong>
                    <span>{sensor.version ? `Agent ${sensor.version} · ` : ''}{relativeTime(sensor.lastSeen)}</span>
                  </div>
                  <StatusPill value={sensor.status} />
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No sensors enrolled" message="Demo mode remains available without a Windows endpoint." icon="info" />
          )}
        </Panel>

        <Panel
          className="dashboard-grid__wide"
          title="Priority alert queue"
          subtitle="Open detections ranked by severity and recency"
          action={<Link className="text-link" to="/alerts">Triage all <Icon name="chevron" size={14} /></Link>}
        >
          {alerts.error ? <ErrorState error={alerts.error} onRetry={alerts.reload} /> : alerts.loading ? (
            <LoadingState label="Loading alerts" />
          ) : alertRows.length ? (
            <div className="compact-table" role="table" aria-label="Priority alerts">
              {alertRows.slice(0, 5).map((alert) => (
                <Link className="compact-table__row" key={alert.id} role="row" to={`/alerts/${encodeURIComponent(alert.id)}`}>
                  <span className="alert-marker" data-severity={alert.severity} aria-hidden="true" />
                  <span className="compact-table__primary">
                    <strong>{alert.title}</strong>
                    <small>{alert.host.name} · {relativeTime(alert.createdAt)}</small>
                  </span>
                  <span className="compact-table__techniques">
                    {alert.techniques.slice(0, 2).map((technique) => <TechniqueTag id={technique} key={technique} />)}
                  </span>
                  <SeverityBadge severity={alert.severity} compact />
                  <Icon name="chevron" size={16} />
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState title="No alerts in the queue" message="Detections will appear here with their matched evidence." icon="alert" />
          )}
        </Panel>

        <Panel title="Severity mix" subtitle="Current alert population by level">
          {alerts.error ? <ErrorState error={alerts.error} onRetry={alerts.reload} /> : (
            <div className="severity-breakdown">
              {(['critical', 'high', 'medium', 'low', 'informational'] as Severity[]).map((level) => {
                const count = alertRows.filter((alert) => alert.severity === level).length;
                const share = alertRows.length ? (count / alertRows.length) * 100 : 0;
                return (
                  <div className="severity-breakdown__row" key={level}>
                    <SeverityBadge severity={level} compact />
                    <div className="progress"><span className={`progress__fill severity-fill--${level}`} style={{ width: `${share}%` }} /></div>
                    <strong>{count}</strong>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
