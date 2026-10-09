export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
export type LiveStatus = 'connecting' | 'connected' | 'disconnected' | 'unsupported';

export interface HealthStatus {
  status: string;
  version?: string;
  database?: string;
  labMode?: boolean;
}

export interface Sensor {
  id: string;
  name: string;
  hostname: string;
  status: string;
  lastSeen?: string;
  enrolledAt?: string;
  version?: string;
  queueDepth?: number;
}

export interface HostRef {
  id?: string;
  name: string;
}

export interface EventRecord {
  id: string;
  eventTime: string;
  ingestedAt?: string;
  category: string;
  action: string;
  host: HostRef;
  user?: string;
  processName?: string;
  processGuid?: string;
  parentProcessGuid?: string;
  commandLine?: string;
  severity: Severity;
  techniques: string[];
  scenarioRunId?: string;
  rawEventId?: string;
  metadata: Record<string, unknown>;
}

export interface AlertEvidence {
  eventId: string;
  summary: string;
  timestamp?: string;
  fields: Record<string, unknown>;
}

export interface Alert {
  id: string;
  title: string;
  ruleId: string;
  ruleName?: string;
  severity: Severity;
  confidence: number;
  status: string;
  createdAt: string;
  host: HostRef;
  reason: string;
  techniques: string[];
  evidence: AlertEvidence[];
  guidance: string[];
  falsePositives: string[];
  scenarioRunId?: string;
  correlationGroupId?: string;
}

export interface DetectionRule {
  id: string;
  title: string;
  description: string;
  status: string;
  severity: Severity;
  confidence?: number;
  source: string;
  version?: string;
  enabled: boolean;
  techniques: string[];
  logSources: string[];
  falsePositives: string[];
  guidance: string[];
  updatedAt?: string;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  techniqueIds: string[];
  platform: string;
  safety: string;
  reversible: boolean;
  supportsDryRun: boolean;
  enabled: boolean;
  labModeRequired: boolean;
  estimatedSeconds?: number;
  lastRun?: ScenarioRun;
}

export interface ScenarioRun {
  id: string;
  scenarioId: string;
  status: string;
  dryRun: boolean;
  startedAt?: string;
  completedAt?: string;
  message?: string;
}

export interface CoverageItem {
  techniqueId: string;
  name: string;
  tactic: string;
  ruleCount: number;
  alertCount: number;
  covered: boolean;
}

export interface CoverageSummary {
  items: CoverageItem[];
  coveredTechniques: number;
  totalTechniques: number;
  ruleCount: number;
  lastUpdated?: string;
}

export type TimelineNodeType =
  | 'process'
  | 'network'
  | 'file'
  | 'registry'
  | 'event'
  | 'alert'
  | 'scenario'
  | 'cluster';

export interface TimelineNode {
  id: string;
  type: TimelineNodeType;
  label: string;
  timestamp?: string;
  host?: string;
  severity: Severity;
  techniques: string[];
  ruleId?: string;
  scenarioRunId?: string;
  eventId?: string;
  evidenceIds: string[];
  memberIds: string[];
  details: Record<string, unknown>;
}

export type TimelineEdgeType = string;

export interface TimelineEdge {
  id: string;
  source: string;
  target: string;
  type: TimelineEdgeType;
  label?: string;
  timestamp?: string;
  count?: number;
}

export interface TimelineGraph {
  nodes: TimelineNode[];
  edges: TimelineEdge[];
  generatedAt?: string;
  truncated?: boolean;
}

export interface LiveMessage {
  type: string;
  timestamp: string;
  payload: unknown;
}

export interface TimelineFilters {
  host: string;
  rule: string;
  technique: string;
  severity: string;
  scenario: string;
  search: string;
}
