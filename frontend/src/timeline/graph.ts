import type { Alert, TimelineEdge, TimelineFilters, TimelineGraph, TimelineNode } from '../types';

function stableNodeId(alertId: string): string {
  return alertId.startsWith('alert:') ? alertId : `alert:${alertId}`;
}

export function mergeAlerts(graph: TimelineGraph, alerts: Alert[]): TimelineGraph {
  const nodes = [...graph.nodes];
  const edges = [...graph.edges];
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edgeIds = new Set(edges.map((edge) => edge.id));
  const eventIndex = new Map<string, string>();
  nodes.forEach((node) => {
    eventIndex.set(node.id, node.id);
    if (node.eventId) eventIndex.set(node.eventId, node.id);
    node.memberIds.forEach((id) => eventIndex.set(id, node.id));
  });

  alerts.forEach((alert) => {
    const existing = nodes.find((node) => node.id === alert.id || node.id === stableNodeId(alert.id));
    const evidenceIds = alert.evidence
      .map((evidence) => eventIndex.get(evidence.eventId) ?? evidence.eventId)
      .filter(Boolean);
    const id = existing?.id ?? stableNodeId(alert.id);
    if (existing) {
      existing.evidenceIds = [...new Set([...existing.evidenceIds, ...evidenceIds])];
      existing.ruleId ||= alert.ruleId;
    } else {
      nodes.push({
        id,
        type: 'alert',
        label: alert.title,
        timestamp: alert.createdAt,
        host: alert.host.name,
        severity: alert.severity,
        techniques: alert.techniques,
        ruleId: alert.ruleId,
        scenarioRunId: alert.scenarioRunId,
        evidenceIds,
        memberIds: [alert.id],
        details: {
          alertId: alert.id,
          status: alert.status,
          confidence: `${alert.confidence}%`,
          reason: alert.reason,
          correlationGroupId: alert.correlationGroupId,
        },
      });
      nodeIds.add(id);
    }

    evidenceIds.forEach((evidenceId, index) => {
      const target = eventIndex.get(evidenceId) ?? evidenceId;
      if (!nodeIds.has(target)) return;
      const edgeId = `alert-evidence:${id}:${target}:${index}`;
      if (!edgeIds.has(edgeId)) {
        edges.push({ id: edgeId, source: id, target, type: 'alert', label: 'matched evidence' });
        edgeIds.add(edgeId);
      }
    });
  });

  return dedupeGraph({ ...graph, nodes, edges });
}

export function dedupeGraph(graph: TimelineGraph): TimelineGraph {
  const nodes = [...new Map(graph.nodes.map((node) => [node.id, node])).values()];
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = [...new Map(graph.edges
    .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target) && edge.source !== edge.target)
    .map((edge) => [edge.id, edge])).values()];
  return { ...graph, nodes, edges };
}

function textBlob(node: TimelineNode): string {
  const details = (() => {
    try {
      return JSON.stringify(node.details);
    } catch {
      return '';
    }
  })();
  return [node.id, node.label, node.host, node.ruleId, node.scenarioRunId, ...node.techniques, details]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

export function filterTimeline(graph: TimelineGraph, filters: TimelineFilters): TimelineGraph {
  const needle = filters.search.trim().toLowerCase();
  const directMatches = new Set(graph.nodes.filter((node) =>
    (!filters.host || node.host === filters.host)
    && (!filters.rule || node.ruleId === filters.rule)
    && (!filters.technique || node.techniques.includes(filters.technique))
    && (!filters.severity || node.severity === filters.severity)
    && (!filters.scenario || node.scenarioRunId === filters.scenario)
    && (!needle || textBlob(node).includes(needle)),
  ).map((node) => node.id));

  // An alert that passes a filter keeps its matched event nodes visible so the explanation remains inspectable.
  const included = new Set(directMatches);
  const evidenceIndex = new Map<string, TimelineNode>();
  graph.nodes.forEach((node) => {
    evidenceIndex.set(node.id, node);
    if (node.eventId) evidenceIndex.set(node.eventId, node);
    node.memberIds.forEach((id) => evidenceIndex.set(id, node));
  });
  graph.nodes.forEach((node) => {
    if (node.type !== 'alert' || !directMatches.has(node.id)) return;
    node.evidenceIds.forEach((evidenceId) => {
      const evidenceNode = evidenceIndex.get(evidenceId);
      if (evidenceNode) included.add(evidenceNode.id);
    });
  });

  const nodes = graph.nodes.filter((node) => included.has(node.id));
  const edges = graph.edges.filter((edge) => included.has(edge.source) && included.has(edge.target));
  return { ...graph, nodes, edges };
}

function minuteBucket(timestamp?: string): number {
  const value = timestamp ? new Date(timestamp).getTime() : 0;
  return Number.isFinite(value) ? Math.floor(value / 300_000) : 0;
}

function clusterCandidate(node: TimelineNode): boolean {
  return !['alert', 'process', 'scenario', 'cluster'].includes(node.type);
}

export function clusterTimeline(graph: TimelineGraph, enabled: boolean, threshold = 80): TimelineGraph {
  if (!enabled || graph.nodes.length <= threshold) return graph;
  const groups = new Map<string, TimelineNode[]>();
  graph.nodes.filter(clusterCandidate).forEach((node) => {
    const key = `${node.host || 'unknown-host'}|${node.type}|${minuteBucket(node.timestamp)}`;
    groups.set(key, [...(groups.get(key) ?? []), node]);
  });
  const clusteredGroups = [...groups.entries()].filter(([, members]) => members.length >= 3);
  if (!clusteredGroups.length) return graph;

  const replacements = new Map<string, string>();
  const clusterNodes: TimelineNode[] = [];
  const removedIds = new Set<string>();
  clusteredGroups.forEach(([key, members], index) => {
    const first = members[0]!;
    const clusterId = `cluster:${index}:${encodeURIComponent(key)}`;
    const memberIds = members.flatMap((member) => [member.id, ...(member.eventId ? [member.eventId] : []), ...member.memberIds]);
    const times = members.map((member) => member.timestamp).filter((value): value is string => Boolean(value)).sort();
    const techniques = [...new Set(members.flatMap((member) => member.techniques))];
    members.forEach((member) => {
      replacements.set(member.id, clusterId);
      removedIds.add(member.id);
    });
    clusterNodes.push({
      id: clusterId,
      type: 'cluster',
      label: `${members.length} ${first.type} events`,
      timestamp: times[0],
      host: first.host,
      severity: members.find((member) => member.severity === 'critical')?.severity
        ?? members.find((member) => member.severity === 'high')?.severity
        ?? members.find((member) => member.severity === 'medium')?.severity
        ?? first.severity,
      techniques,
      scenarioRunId: first.scenarioRunId,
      evidenceIds: [],
      memberIds: [...new Set(memberIds)],
      details: {
        memberCount: members.length,
        category: first.type,
        host: first.host,
        from: times[0],
        to: times[times.length - 1],
        memberLabels: members.slice(0, 12).map((member) => member.label),
      },
    });
  });

  const edgeMap = new Map<string, TimelineEdge>();
  graph.edges.forEach((edge) => {
    const source = replacements.get(edge.source) ?? edge.source;
    const target = replacements.get(edge.target) ?? edge.target;
    if (source === target) return;
    const key = `${source}|${target}|${edge.type}`;
    const existing = edgeMap.get(key);
    if (existing) {
      existing.count = (existing.count ?? 1) + (edge.count ?? 1);
    } else {
      edgeMap.set(key, { ...edge, id: `clustered:${key}`, source, target, count: edge.count ?? 1 });
    }
  });

  return {
    ...graph,
    nodes: [...graph.nodes.filter((node) => !removedIds.has(node.id)), ...clusterNodes],
    edges: [...edgeMap.values()],
  };
}

export function graphFacets(graph: TimelineGraph) {
  const sorted = (values: Array<string | undefined>) => [...new Set(values.filter((value): value is string => Boolean(value)))].sort();
  return {
    hosts: sorted(graph.nodes.map((node) => node.host)),
    rules: sorted(graph.nodes.map((node) => node.ruleId)),
    techniques: sorted(graph.nodes.flatMap((node) => node.techniques)),
    scenarios: sorted(graph.nodes.map((node) => node.scenarioRunId)),
  };
}

export function findAlertNode(graph: TimelineGraph, alertId: string): TimelineNode | undefined {
  return graph.nodes.find((node) =>
    node.type === 'alert'
    && (node.id === alertId || node.id === stableNodeId(alertId) || node.memberIds.includes(alertId)),
  );
}
