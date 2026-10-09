import { useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import { Icon } from '../components/Icon';
import { PageHeader, TechniqueTag } from '../components/Page';
import { EmptyState, ErrorState, InlineNotice, LoadingState, StatusPill } from '../components/Status';
import { useLive } from '../context/LiveContext';
import { useApiQuery } from '../hooks/useApiQuery';
import type { Scenario, ScenarioRun, Sensor } from '../types';
import { formatDateTime } from '../utils/format';

function ScenarioDialog({ scenario, labMode, adminKey, sensors, onClose, onRun }: {
  scenario: Scenario;
  labMode: boolean;
  adminKey: string;
  sensors: Sensor[];
  onClose: () => void;
  onRun: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [dryRun, setDryRun] = useState(true);
  const [confirmation, setConfirmation] = useState('');
  const [sensorId, setSensorId] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<Error>();
  const [run, setRun] = useState<ScenarioRun>();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    dialog.showModal();
    const handleCancel = (event: Event) => {
      event.preventDefault();
      onClose();
    };
    dialog.addEventListener('cancel', handleCancel);
    return () => dialog.removeEventListener('cancel', handleCancel);
  }, [onClose]);

  const canSubmit = Boolean(adminKey) && (dryRun || (labMode && Boolean(sensorId) && confirmation === 'RUN IN LAB'));

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(undefined);
    try {
      const result = await api.runScenario(scenario.id, dryRun, adminKey, sensorId || undefined);
      setRun(result);
      onRun();
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error('Unable to start scenario.'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <dialog className="scenario-dialog" ref={ref} aria-labelledby="scenario-dialog-title">
      <form method="dialog" onSubmit={(event) => void submit(event)}>
        <div className="scenario-dialog__header">
          <span className="scenario-icon"><Icon name="scenario" size={22} /></span>
          <div><span className="eyebrow">Controlled simulation</span><h2 id="scenario-dialog-title">{scenario.name}</h2></div>
          <button className="icon-button" aria-label="Close scenario dialog" onClick={onClose} type="button"><Icon name="close" /></button>
        </div>
        {run ? (
          <div className="scenario-dialog__result">
            <InlineNotice tone={['failed', 'error'].includes(run.status) ? 'danger' : 'success'}>
              <strong>Run {run.status}</strong>
              <p>{run.message || `Scenario run ${run.id} was accepted by the backend.`}</p>
            </InlineNotice>
            <dl className="summary-grid">
              <div><dt>Run ID</dt><dd><code>{run.id}</code></dd></div>
              <div><dt>Mode</dt><dd>{run.dryRun ? 'Dry run' : 'Lab execution'}</dd></div>
              <div><dt>Started</dt><dd>{run.startedAt ? formatDateTime(run.startedAt) : 'Queued'}</dd></div>
              <div><dt>Status</dt><dd><StatusPill value={run.status} /></dd></div>
            </dl>
            <button className="button button--primary" onClick={onClose} type="button">Done</button>
          </div>
        ) : (
          <>
            <p>{scenario.description}</p>
            <InlineNotice tone="warning">
              <strong>Safety boundary</strong>
              <p>{scenario.safety}. Cleanup remains enforced by the simulation runner.</p>
            </InlineNotice>
            <fieldset className="mode-picker">
              <legend>Execution mode</legend>
              <label className={`mode-option${dryRun ? ' mode-option--selected' : ''}`}>
                <input checked={dryRun} name="mode" onChange={() => setDryRun(true)} type="radio" />
                <span><strong>Dry run</strong><small>Preview validated actions without changing the lab endpoint.</small></span>
                <span className="recommended-label">Recommended</span>
              </label>
              <label className={`mode-option${!dryRun ? ' mode-option--selected' : ''}${!labMode ? ' mode-option--disabled' : ''}`}>
                <input checked={!dryRun} disabled={!labMode} name="mode" onChange={() => setDryRun(false)} type="radio" />
                <span><strong>Execute in lab</strong><small>Run reversible behavior inside the explicitly enabled Windows lab.</small></span>
              </label>
            </fieldset>
            {!labMode ? <InlineNotice>Live execution is unavailable because the API does not report lab mode as enabled. Dry-run remains available.</InlineNotice> : null}
            {!dryRun ? (
              <div className="live-target-fields">
                <label>
                  <span>Target enrolled sensor</span>
                  <select aria-label="Target enrolled sensor" onChange={(event) => setSensorId(event.target.value)} required value={sensorId}>
                    <option value="">Select a sensor explicitly</option>
                    {sensors.map((sensor) => <option key={sensor.id} value={sensor.id}>{sensor.hostname} · {sensor.status}</option>)}
                  </select>
                </label>
                {!sensors.length ? <InlineNotice tone="danger">No enrolled sensor is available. Live execution cannot be requested.</InlineNotice> : null}
                <label className="confirmation-field">
                  <span>Type <code>RUN IN LAB</code> to confirm scoped execution</span>
                  <input autoComplete="off" onChange={(event) => setConfirmation(event.target.value)} placeholder="RUN IN LAB" value={confirmation} />
                </label>
              </div>
            ) : null}
            {error ? <InlineNotice tone="danger"><strong>Scenario was not started</strong><p>{error.message}</p></InlineNotice> : null}
            <div className="scenario-dialog__actions">
              <button className="button button--secondary" onClick={onClose} type="button">Cancel</button>
              <button className="button button--primary" disabled={!canSubmit || submitting} title={!adminKey ? 'Enter the local admin key before requesting a scenario run' : undefined} type="submit">
                {submitting ? <span className="spinner spinner--small" /> : <Icon name={dryRun ? 'search' : 'play'} size={16} />}
                {submitting ? 'Submitting…' : dryRun ? 'Preview scenario' : 'Start lab run'}
              </button>
            </div>
          </>
        )}
      </form>
    </dialog>
  );
}

export default function ScenariosPage() {
  const scenarios = useApiQuery(api.scenarios);
  const sensors = useApiQuery(api.sensors);
  const health = useApiQuery(api.health, false);
  const { markMutation } = useLive();
  const [selected, setSelected] = useState<Scenario>();
  const [adminKey, setAdminKey] = useState('');
  const [seed, setSeed] = useState('1337');
  const [seedState, setSeedState] = useState<{ loading: boolean; message?: string; error?: string }>({ loading: false });

  const seedDemo = async (event: React.FormEvent) => {
    event.preventDefault();
    const value = Number(seed);
    if (!Number.isInteger(value) || value < 0 || value > 2_147_483_647) {
      setSeedState({ loading: false, error: 'Seed must be an integer from 0 through 2147483647.' });
      return;
    }
    setSeedState({ loading: true });
    try {
      const result = await api.seedDemo(value, adminKey);
      setSeedState({ loading: false, message: result.message });
      markMutation();
    } catch (caught) {
      setSeedState({ loading: false, error: caught instanceof Error ? caught.message : 'Unable to seed demo data.' });
    }
  };

  const handleRun = () => {
    markMutation();
    scenarios.reload();
  };

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Behavior simulation"
        title="Scenario control"
        description="Preview or run safe, reversible adversary behaviors against an explicitly enabled isolated lab."
        actions={<span className={`lab-mode-badge${health.data?.labMode ? ' lab-mode-badge--enabled' : ''}`}><span /> Lab mode {health.data?.labMode ? 'enabled' : 'disabled'}</span>}
      />

      <section className="admin-key-panel">
        <div><Icon name="shield" size={19} /><span><strong>Privileged actions are locked</strong><small>The key is held in this page's memory only and is never persisted or included in a URL.</small></span></div>
        <label><span>Admin key</span><input aria-label="Admin key" autoComplete="off" onChange={(event) => setAdminKey(event.target.value)} placeholder="Enter local admin key" spellCheck={false} type="password" value={adminKey} /></label>
        <StatusPill value={adminKey ? 'unlocked' : 'locked'} />
      </section>

      <section className="demo-seed-panel">
        <div className="demo-seed-panel__icon"><Icon name="spark" size={24} /></div>
        <div><h2>Deterministic demo dataset</h2><p>Generate repeatable positive detections and near misses without a Windows sensor.</p></div>
        <form onSubmit={(event) => void seedDemo(event)}>
          <label><span>Seed</span><input inputMode="numeric" min="0" onChange={(event) => setSeed(event.target.value)} type="number" value={seed} /></label>
          <button className="button button--primary" disabled={seedState.loading || !adminKey} title={!adminKey ? 'Enter the local admin key first' : undefined} type="submit">
            {seedState.loading ? <span className="spinner spinner--small" /> : <Icon name="database" size={16} />} {seedState.loading ? 'Seeding…' : 'Seed demo'}
          </button>
        </form>
      </section>
      {seedState.message ? <InlineNotice tone="success"><strong>Demo data ready</strong><p>{seedState.message}</p></InlineNotice> : null}
      {seedState.error ? <InlineNotice tone="danger"><strong>Demo seed failed</strong><p>{seedState.error}</p></InlineNotice> : null}

      <div className="section-title"><div><h2>Available simulations</h2><p>Every scenario is dry-run capable and cleanup-aware.</p></div><span className="count-label">{scenarios.data?.length ?? 0} scenarios</span></div>

      {scenarios.error ? <ErrorState error={scenarios.error} onRetry={scenarios.reload} /> : scenarios.loading ? (
        <LoadingState label="Loading simulation catalog" />
      ) : scenarios.data?.length ? (
        <section className="scenario-grid" aria-label="Simulation scenarios">
          {scenarios.data.map((scenario) => (
            <article className="scenario-card" key={scenario.id}>
              <div className="scenario-card__header">
                <span className="scenario-icon"><Icon name="scenario" size={21} /></span>
                <div><span className="mono-label">{scenario.id}</span><h2>{scenario.name}</h2></div>
                <StatusPill value={scenario.enabled ? 'available' : 'disabled'} />
              </div>
              <p>{scenario.description}</p>
              <div className="tag-row">{scenario.techniqueIds.map((id) => <TechniqueTag id={id} key={id} />)}</div>
              <dl className="scenario-facts">
                <div><Icon name="shield" size={15} /><dt>Boundary</dt><dd>{scenario.safety}</dd></div>
                <div><Icon name="refresh" size={15} /><dt>Cleanup</dt><dd>{scenario.reversible ? 'Reversible' : 'Review required'}</dd></div>
                <div><Icon name="host" size={15} /><dt>Platform</dt><dd>{scenario.platform}</dd></div>
              </dl>
              <div className="scenario-card__footer">
                <span>{scenario.lastRun ? `Last run ${scenario.lastRun.status}` : 'Not run in this environment'}</span>
                <button className="button button--secondary button--small" disabled={!scenario.enabled} onClick={() => setSelected(scenario)} type="button">Configure <Icon name="chevron" size={14} /></button>
              </div>
            </article>
          ))}
        </section>
      ) : <EmptyState title="No scenarios available" message="The backend did not return a simulation catalog." icon="info" />}

      {selected ? <ScenarioDialog adminKey={adminKey} labMode={health.data?.labMode === true} onClose={() => setSelected(undefined)} onRun={handleRun} scenario={selected} sensors={sensors.data ?? []} /> : null}
    </div>
  );
}
