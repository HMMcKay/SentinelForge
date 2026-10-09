import type {
  Alert,
  AlertEvidence,
  CoverageItem,
  CoverageSummary,
  DetectionRule,
  EventRecord,
  HealthStatus,
  Scenario,
  ScenarioRun,
  Sensor,
  Severity,
  TimelineEdge,
  TimelineGraph,
  TimelineNode,
  TimelineNodeType,
} from '../types';

type JsonRecord = Record<string, unknown>;

export function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

function text(value: unknown, fallback = ''): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
}

function numberValue(value: unknown, fallback = 0): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function bool(value: unknown, fallback = false): boolean {
  if (typeof value === 'boolean') return value;
  if (value === 'true' || value === 1 || value === '1') return true;
  if (value === 'false' || value === 0 || value === '0') return false;
  return fallback;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function strings(value: unknown): string[] {
  if (typeof value === 'string') return value ? [value] : [];
  return list(value).map((item) => text(item)).filter(Boolean);
}

export function severity(value: unknown): Severity {
  const normalized = text(value, 'unknown').toLowerCase();
  if (normalized === 'info') return 'informational';
  if (['critical', 'high', 'medium', 'low', 'informational'].includes(normalized)) {
    return normalized as Severity;
  }
  return 'unknown';
}

export function unwrapList(payload: unknown, keys: string[] = []): unknown[] {
  if (Array.isArray(payload)) return payload;
  const record = asRecord(payload);
  for (const key of [...keys, 'items', 'results', 'data']) {
    if (Array.isArray(record[key])) return record[key] as unknown[];
  }
  return [];
}

function hostFrom(record: JsonRecord): { id?: string; name: string } {
  const data = asRecord(record.data);
  const host = asRecord(record.host ?? data.host);
  const id = text(host.id ?? record.host_id) || undefined;
  return {
    ...(id ? { id } : {}),
    name: text(host.name ?? host.hostname ?? record.hostname ?? record.host_name, 'unknown-host'),
  };
}

function eventCategory(record: JsonRecord): string {
  const explicit = text(record.category ?? record.event_category ?? record.type);
  if (explicit && explicit !== 'event') return explicit;
  const eventType = text(record.event_type).toLowerCase();
  if (eventType.startsWith('process_') || eventType === 'powershell') return 'process';
  if (eventType.startsWith('file_')) return 'file';
  if (eventType.startsWith('registry_')) return 'registry';
  if (eventType === 'dns_query' || eventType === 'network_connection') return 'network';
  return explicit || eventType.split('_', 1)[0] || 'event';
}

export function adaptHealth(payload: unknown): HealthStatus {
  const item = asRecord(payload);
  return {
    status: text(item.status, 'unknown'),
    version: text(item.version) || undefined,
    database: text(item.database ?? item.database_status) || undefined,
    labMode: typeof item.lab_mode === 'boolean' ? item.lab_mode : undefined,
  };
}

export function adaptSensor(payload: unknown): Sensor {
  const item = asRecord(payload);
  const health = asRecord(item.health);
  return {
    id: text(item.id ?? item.sensor_id, 'unknown'),
    name: text(item.name ?? item.hostname, 'Unnamed sensor'),
    hostname: text(item.hostname ?? item.host_name ?? item.name, 'unknown-host'),
    status: text(health.status ?? item.status, 'unknown').toLowerCase(),
    lastSeen: text(item.last_seen_at ?? item.last_seen ?? item.lastSeen ?? health.received_at) || undefined,
    enrolledAt: text(item.enrolled_at ?? item.created_at) || undefined,
    version: text(item.version ?? item.agent_version ?? health.agent_version) || undefined,
    queueDepth: item.queue_depth === undefined && health.spool_event_count === undefined
      ? undefined
      : numberValue(item.queue_depth ?? health.spool_event_count),
  };
}

export function adaptEvent(payload: unknown): EventRecord {
  const item = asRecord(payload);
  const data = asRecord(item.data);
  const process = asRecord(item.process ?? data.process);
  const user = asRecord(item.user ?? item.user_info ?? data.user);
  const attack = asRecord(item.attack);
  return {
    id: text(item.id ?? item.event_id ?? item.source_event_id, 'unknown'),
    eventTime: text(item.event_time ?? item.timestamp ?? item.occurred_at),
    ingestedAt: text(item.ingested_at ?? item.ingest_time ?? item.created_at) || undefined,
    category: eventCategory(item),
    action: text(item.action ?? item.event_action ?? item.event_type ?? item.name, 'observed'),
    host: hostFrom(item),
    user: text(user.name ?? user.username) || undefined,
    processName: text(process.name ?? item.process_name ?? process.executable) || undefined,
    processGuid: text(process.entity_id ?? process.guid ?? item.process_guid) || undefined,
    parentProcessGuid: text(process.parent_entity_id ?? item.parent_process_guid) || undefined,
    commandLine: text(process.command_line ?? item.command_line) || undefined,
    severity: severity(item.severity),
    techniques: strings(item.techniques ?? item.attack_techniques ?? item.attack_tags ?? data.attack_tags ?? attack.techniques),
    scenarioRunId: text(item.scenario_run_id) || undefined,
    rawEventId: text(item.raw_event_id) || undefined,
    metadata: asRecord(item.metadata ?? data.metadata),
  };
}

function adaptEvidence(payload: unknown): AlertEvidence {
  const item = asRecord(payload);
  const event = asRecord(item.event);
  return {
    eventId: text(item.event_id ?? event.id ?? item.id, 'unknown'),
    summary: text(item.summary ?? item.description ?? item.reason, 'Matched event'),
    timestamp: text(item.timestamp ?? item.event_time ?? event.event_time) || undefined,
    fields: Object.keys(asRecord(item.fields)).length
      ? asRecord(item.fields)
      : Object.keys(event).length
        ? event
        : asRecord(item.details),
  };
}

export function adaptAlert(payload: unknown): Alert {
  const item = asRecord(payload);
  const rule = asRecord(item.rule);
  const evidence = unwrapList(item.evidence ?? item.matched_events, ['events']).map(adaptEvidence);
  const confidence = numberValue(item.confidence, 0);
  return {
    id: text(item.id ?? item.alert_id, 'unknown'),
    title: text(item.title ?? item.name ?? rule.title, 'Untitled alert'),
    ruleId: text(item.rule_id ?? rule.id, 'unknown-rule'),
    ruleName: text(item.rule_name ?? rule.title) || undefined,
    severity: severity(item.severity ?? rule.severity),
    confidence: confidence <= 1 ? Math.round(confidence * 100) : Math.round(confidence),
    status: text(item.status, 'open').toLowerCase(),
    createdAt: text(item.created_at ?? item.timestamp ?? item.first_seen),
    host: hostFrom(item),
    reason: text(item.reason ?? item.why ?? item.explanation ?? item.description, 'Detection criteria matched.'),
    techniques: strings(item.techniques ?? item.attack_techniques ?? item.attack_tags ?? rule.techniques),
    evidence,
    guidance: strings(item.guidance ?? item.investigation_guidance ?? item.investigation ?? rule.guidance),
    falsePositives: strings(item.false_positives ?? rule.false_positives),
    scenarioRunId: text(item.scenario_run_id) || undefined,
    correlationGroupId: text(item.correlation_group_id) || undefined,
  };
}

export function adaptRule(payload: unknown): DetectionRule {
  const item = asRecord(payload);
  const definition = asRecord(item.definition);
  return {
    id: text(item.id ?? item.rule_id, 'unknown-rule'),
    title: text(item.title ?? item.name, 'Untitled rule'),
    description: text(item.description, 'No description provided.'),
    status: text(item.status, 'stable'),
    severity: severity(item.severity ?? item.level),
    confidence: item.confidence === undefined ? undefined : numberValue(item.confidence),
    source: text(item.source ?? item.rule_type ?? definition.type, 'sigma'),
    version: text(item.version ?? item.current_version) || undefined,
    enabled: bool(item.enabled, true),
    techniques: strings(item.techniques ?? item.attack_techniques ?? item.attack_tags ?? item.tags)
      .filter((value) => /^T\d{4}(?:\.\d{3})?$/.test(value.replace('attack.', '').toUpperCase()))
      .map((value) => value.replace('attack.', '').toUpperCase()),
    logSources: strings(item.log_sources ?? item.logsource ?? definition.log_sources),
    falsePositives: strings(item.false_positives),
    guidance: strings(item.guidance ?? item.investigation_guidance ?? item.investigation),
    updatedAt: text(item.updated_at) || undefined,
  };
}

export function adaptRun(payload: unknown): ScenarioRun {
  const item = asRecord(payload);
  return {
    id: text(item.id ?? item.run_id, 'pending'),
    scenarioId: text(item.scenario_id, 'unknown-scenario'),
    status: text(item.status, 'queued'),
    dryRun: bool(item.dry_run, true),
    startedAt: text(item.started_at ?? item.created_at) || undefined,
    completedAt: text(item.completed_at) || undefined,
    message: text(item.message ?? item.detail) || undefined,
  };
}

export function adaptScenario(payload: unknown): Scenario {
  const item = asRecord(payload);
  const lastRunRaw = item.last_run;
  const platforms = strings(item.supported_platforms);
  const safetyNotes = strings(item.safety_notes);
  return {
    id: text(item.id ?? item.scenario_id, 'unknown-scenario'),
    name: text(item.name ?? item.title, 'Unnamed scenario'),
    description: text(item.description, 'No description provided.'),
    techniqueIds: strings(item.technique_ids ?? item.techniques ?? item.attack_techniques),
    platform: text(item.platform) || (platforms.length ? platforms.join(', ') : 'Windows'),
    safety: text(item.safety ?? item.safety_summary) || (safetyNotes.length ? safetyNotes.join('; ') : 'Scoped, reversible lab behavior'),
    reversible: bool(item.reversible, true),
    supportsDryRun: bool(item.supports_dry_run, true),
    enabled: bool(item.enabled, true),
    labModeRequired: bool(item.lab_mode_required, true),
    estimatedSeconds: item.estimated_seconds === undefined ? undefined : numberValue(item.estimated_seconds),
    lastRun: lastRunRaw ? adaptRun(lastRunRaw) : undefined,
  };
}

function adaptCoverageItem(payload: unknown): CoverageItem {
  const item = asRecord(payload);
  const ruleCount = numberValue(item.rule_count ?? item.rules);
  return {
    techniqueId: text(item.technique_id ?? item.id, 'unknown'),
    name: text(item.name ?? item.technique_name, 'Unknown technique'),
    tactic: text(item.tactic ?? item.tactic_name, 'Uncategorized'),
    ruleCount,
    alertCount: numberValue(item.alert_count ?? item.alerts),
    covered: bool(item.covered, ruleCount > 0),
  };
}

export function adaptCoverage(payload: unknown): CoverageSummary {
  const root = asRecord(payload);
  const summary = asRecord(root.summary);
  const items = unwrapList(payload, ['techniques', 'coverage']).map(adaptCoverageItem);
  const covered = items.filter((item) => item.covered).length;
  return {
    items,
    coveredTechniques: numberValue(summary.techniques_covered ?? summary.covered_techniques ?? summary.covered ?? root.covered_techniques ?? root.covered, covered),
    totalTechniques: numberValue(summary.techniques_cataloged ?? summary.total_techniques ?? summary.total ?? root.total_techniques ?? root.total, items.length),
    ruleCount: numberValue(summary.enabled_rules ?? summary.rule_count ?? root.rule_count, items.reduce((sum, item) => sum + item.ruleCount, 0)),
    lastUpdated: text(summary.last_updated ?? root.last_updated ?? root.generated_at) || undefined,
  };
}

function timelineType(value: unknown): TimelineNodeType {
  const normalized = text(value, 'event').toLowerCase();
  if (['process', 'network', 'file', 'registry', 'alert', 'scenario', 'cluster'].includes(normalized)) {
    return normalized as TimelineNodeType;
  }
  return 'event';
}

function adaptTimelineNode(payload: unknown): TimelineNode {
  const outer = asRecord(payload);
  const item = Object.keys(asRecord(outer.data)).length ? { ...outer, ...asRecord(outer.data) } : outer;
  const nestedEvent = asRecord(item.event);
  const nestedAlert = asRecord(item.alert);
  const event = Object.keys(nestedEvent).length ? adaptEvent(nestedEvent) : undefined;
  const alertHost = hostFrom(nestedAlert);
  return {
    id: text(item.id, 'unknown-node'),
    type: timelineType(
      text(item.type ?? item.node_type ?? item.category) === 'event' && event
        ? event.category
        : item.type ?? item.node_type ?? item.category ?? event?.category,
    ),
    label: text(item.label ?? item.name ?? item.action, 'Observed event'),
    timestamp: text(item.timestamp ?? item.event_time ?? item.created_at) || undefined,
    host: text(item.host ?? item.hostname ?? asRecord(item.host_ref).name) || event?.host.name || (Object.keys(nestedAlert).length ? alertHost.name : undefined),
    severity: severity(item.severity ?? nestedAlert.severity ?? event?.severity),
    techniques: strings(item.techniques ?? item.attack_techniques ?? nestedAlert.attack_tags ?? nestedEvent.attack_tags),
    ruleId: text(item.rule_id ?? nestedAlert.rule_id) || undefined,
    scenarioRunId: text(item.scenario_run_id ?? nestedAlert.scenario_run_id ?? nestedEvent.scenario_run_id) || undefined,
    eventId: text(item.event_id ?? nestedEvent.id) || undefined,
    evidenceIds: strings(item.evidence_ids ?? item.evidence),
    memberIds: strings(item.member_ids),
    details: Object.keys(asRecord(item.details)).length
      ? asRecord(item.details)
      : Object.keys(asRecord(nestedEvent.data)).length
        ? asRecord(nestedEvent.data)
        : Object.keys(nestedAlert).length
          ? nestedAlert
          : item,
  };
}

function adaptTimelineEdge(payload: unknown, index: number): TimelineEdge {
  const outer = asRecord(payload);
  const item = Object.keys(asRecord(outer.data)).length ? { ...outer, ...asRecord(outer.data) } : outer;
  const source = text(item.source);
  const target = text(item.target);
  return {
    id: text(item.id, `edge-${index}-${source}-${target}`),
    source,
    target,
    type: text(item.type ?? item.edge_type, 'correlation').toLowerCase(),
    label: text(item.label) || undefined,
    timestamp: text(item.timestamp) || undefined,
    count: item.count === undefined ? undefined : numberValue(item.count),
  };
}

export function graphFromEvents(events: EventRecord[]): TimelineGraph {
  const nodes: TimelineNode[] = [];
  const edges: TimelineEdge[] = [];
  const processNodeIds = new Map<string, string>();

  for (const event of events) {
    const nodeId = `event:${event.id}`;
    nodes.push({
      id: nodeId,
      type: event.category === 'process' ? 'process' : timelineType(event.category),
      label: event.processName || event.action,
      timestamp: event.eventTime,
      host: event.host.name,
      severity: event.severity,
      techniques: event.techniques,
      scenarioRunId: event.scenarioRunId,
      eventId: event.id,
      evidenceIds: [],
      memberIds: [],
      details: event.metadata,
    });
    if (event.processGuid) processNodeIds.set(event.processGuid, nodeId);
  }

  for (const event of events) {
    if (!event.parentProcessGuid || !event.processGuid) continue;
    const source = processNodeIds.get(event.parentProcessGuid);
    const target = processNodeIds.get(event.processGuid);
    if (source && target) {
      edges.push({ id: `process:${source}:${target}`, source, target, type: 'process' });
    }
  }
  return { nodes, edges };
}

export function adaptTimeline(payload: unknown): TimelineGraph {
  const root = asRecord(payload);
  const meta = asRecord(root.meta);
  const rawNodes = unwrapList(root.nodes, ['nodes']);
  const rawEvents = unwrapList(root.events, ['events']);
  const base = rawNodes.length
    ? { nodes: rawNodes.map(adaptTimelineNode), edges: [] as TimelineEdge[] }
    : graphFromEvents(rawEvents.map(adaptEvent));
  const rawEdges = unwrapList(root.edges, ['edges']);
  if (rawEdges.length) base.edges = rawEdges.map(adaptTimelineEdge);
  return {
    ...base,
    generatedAt: text(root.generated_at ?? meta.generated_at) || undefined,
    truncated: bool(root.truncated ?? meta.truncated),
  };
}
