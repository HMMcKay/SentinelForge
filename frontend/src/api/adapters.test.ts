import { adaptAlert, adaptCoverage, adaptEvent, adaptRule, adaptScenario, adaptSensor, adaptTimeline, unwrapList } from './adapters';

describe('API adapters', () => {
  it('unwraps collection envelopes used by the backend', () => {
    expect(unwrapList({ items: [{ id: 1 }], total: 1 })).toEqual([{ id: 1 }]);
  });

  it('normalizes alert evidence and fractional confidence', () => {
    const alert = adaptAlert({
      id: 'alert-1',
      title: 'Encoded PowerShell',
      rule_id: 'SF-PS-001',
      severity: 'high',
      confidence: 0.92,
      created_at: '2026-01-01T00:00:00Z',
      host: { name: 'LAB-01' },
      techniques: ['T1059.001'],
      evidence: [{ event_id: 'event-7', summary: 'Encoded command line', fields: { process_name: 'powershell.exe' } }],
    });

    expect(alert.confidence).toBe(92);
    expect(alert.host.name).toBe('LAB-01');
    expect(alert.evidence[0]?.eventId).toBe('event-7');
  });

  it('reads nested ATT&CK coverage summaries', () => {
    const coverage = adaptCoverage({
      items: [{ technique_id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', rule_count: 2, alert_count: 3 }],
      summary: { covered_techniques: 1, total_techniques: 9, rule_count: 2 },
    });
    expect(coverage.coveredTechniques).toBe(1);
    expect(coverage.totalTechniques).toBe(9);
    expect(coverage.items[0]?.covered).toBe(true);
  });

  it('normalizes the backend event serializer contract', () => {
    const event = adaptEvent({
      id: 'db-event-1', source_event_id: 'sysmon:1', event_time: '2026-07-27T18:00:00Z',
      ingest_time: '2026-07-27T18:00:01Z', event_type: 'powershell', attack_tags: ['T1059.001'],
      data: {
        host: { hostname: 'LAB-01' }, user: { name: 'lab-user' },
        process: { guid: 'process-1', name: 'powershell.exe', command_line: 'powershell.exe -NoProfile' },
        metadata: { source: 'sysmon' },
      },
    });
    expect(event).toMatchObject({
      id: 'db-event-1', ingestedAt: '2026-07-27T18:00:01Z', action: 'powershell',
      category: 'process', host: { name: 'LAB-01' }, user: 'lab-user', processName: 'powershell.exe',
      processGuid: 'process-1', techniques: ['T1059.001'],
    });
  });

  it('normalizes nested sensor health, rules, and scenarios', () => {
    expect(adaptSensor({
      id: 'sensor-1', name: 'Lab sensor', status: 'enrolled', last_seen_at: '2026-07-27T18:00:00Z',
      health: { status: 'healthy', agent_version: '0.1.0', spool_event_count: 4 },
    })).toMatchObject({ hostname: 'Lab sensor', status: 'healthy', version: '0.1.0', queueDepth: 4 });
    expect(adaptRule({
      id: 'SF-1', title: 'Rule', attack_tags: ['T1059.001'], investigation: 'Review lineage.',
    })).toMatchObject({ techniques: ['T1059.001'], guidance: ['Review lineage.'] });
    expect(adaptScenario({
      id: 'scenario-1', name: 'Scenario', supported_platforms: ['windows', 'synthetic'],
      safety_notes: ['Lab mode required', 'Cleanup verified'],
    })).toMatchObject({ platform: 'windows, synthetic', safety: 'Lab mode required; Cleanup verified' });
  });

  it('accepts Cytoscape-shaped graph records', () => {
    const graph = adaptTimeline({
      nodes: [{ data: { id: 'p1', type: 'process', label: 'cmd.exe', host: 'LAB-01' } }],
      edges: [],
    });
    expect(graph.nodes).toHaveLength(1);
    expect(graph.nodes[0]).toMatchObject({ id: 'p1', type: 'process', label: 'cmd.exe' });
  });

  it('reads nested backend timeline event and alert records plus meta truncation', () => {
    const graph = adaptTimeline({
      nodes: [
        { id: 'event:e1', type: 'event', label: 'powershell', timestamp: '2026-07-27T18:00:00Z', event: {
          id: 'e1', event_time: '2026-07-27T18:00:00Z', event_type: 'powershell', attack_tags: ['T1059.001'],
          data: { host: { hostname: 'LAB-01' }, process: { name: 'powershell.exe' } },
        } },
        { id: 'alert:a1', type: 'alert', label: 'Alert', alert: { id: 'a1', rule_id: 'SF-1', severity: 'high', attack_tags: ['T1059.001'], host_id: 'h1' } },
      ],
      edges: [], meta: { truncated: true },
    });
    expect(graph.truncated).toBe(true);
    expect(graph.nodes[0]).toMatchObject({ type: 'process', eventId: 'e1', host: 'LAB-01', techniques: ['T1059.001'] });
    expect(graph.nodes[1]).toMatchObject({ ruleId: 'SF-1', severity: 'high', techniques: ['T1059.001'] });
  });
});
