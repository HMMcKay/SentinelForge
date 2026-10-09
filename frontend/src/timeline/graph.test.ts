import type { Alert, TimelineGraph, TimelineNode } from '../types';
import { clusterTimeline, filterTimeline, mergeAlerts } from './graph';

function node(id: string, overrides: Partial<TimelineNode> = {}): TimelineNode {
  return {
    id,
    type: 'event',
    label: id,
    timestamp: '2026-01-01T00:00:00Z',
    host: 'LAB-01',
    severity: 'medium',
    techniques: [],
    evidenceIds: [],
    memberIds: [],
    details: {},
    ...overrides,
  };
}

const alert: Alert = {
  id: 'a1',
  title: 'Suspicious chain',
  ruleId: 'SF-001',
  severity: 'high',
  confidence: 90,
  status: 'open',
  createdAt: '2026-01-01T00:01:00Z',
  host: { name: 'LAB-01' },
  reason: 'A sequence matched.',
  techniques: ['T1059.001'],
  evidence: [{ eventId: 'e1', summary: 'process start', fields: {} }],
  guidance: [],
  falsePositives: [],
};

describe('timeline transformations', () => {
  it('merges alerts and connects them to evidence event IDs', () => {
    const graph = mergeAlerts({ nodes: [node('n1', { eventId: 'e1' })], edges: [] }, [alert]);
    expect(graph.nodes.find((item) => item.id === 'alert:a1')?.evidenceIds).toEqual(['n1']);
    expect(graph.edges).toEqual(expect.arrayContaining([expect.objectContaining({ source: 'alert:a1', target: 'n1', type: 'alert' })]));
  });

  it('retains evidence context when filtering for an alert rule', () => {
    const merged = mergeAlerts({ nodes: [node('n1', { eventId: 'e1' })], edges: [] }, [alert]);
    const filtered = filterTimeline(merged, { host: '', rule: 'SF-001', technique: '', severity: '', scenario: '', search: '' });
    expect(filtered.nodes.map((item) => item.id).sort()).toEqual(['alert:a1', 'n1']);
  });

  it('clusters high-volume event groups while retaining source identities', () => {
    const nodes = Array.from({ length: 9 }, (_, index) => node(`n${index}`, { eventId: `e${index}`, type: 'registry' }));
    const graph: TimelineGraph = { nodes, edges: [] };
    const clustered = clusterTimeline(graph, true, 5);
    expect(clustered.nodes).toHaveLength(1);
    expect(clustered.nodes[0]?.type).toBe('cluster');
    expect(clustered.nodes[0]?.memberIds).toEqual(expect.arrayContaining(['n0', 'e0', 'n8', 'e8']));
  });

  it('does not cluster below the safety threshold', () => {
    const graph: TimelineGraph = { nodes: [node('a'), node('b'), node('c')], edges: [] };
    expect(clusterTimeline(graph, true, 10)).toBe(graph);
  });
});
