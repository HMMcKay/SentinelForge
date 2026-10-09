import {
  adaptAlert,
  adaptCoverage,
  adaptEvent,
  adaptHealth,
  adaptRule,
  adaptRun,
  adaptScenario,
  adaptSensor,
  adaptTimeline,
  asRecord,
  unwrapList,
} from './adapters';
import type {
  Alert,
  CoverageSummary,
  DetectionRule,
  EventRecord,
  HealthStatus,
  Scenario,
  ScenarioRun,
  Sensor,
  TimelineGraph,
} from '../types';

const configuredBase = import.meta.env.VITE_API_BASE_URL || '/api/v1';
export const API_BASE = configuredBase.replace(/\/$/, '');

export class ApiError extends Error {
  readonly status: number;
  readonly requestId?: string;

  constructor(message: string, status: number, requestId?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.requestId = requestId;
  }
}

function errorMessage(payload: unknown, fallback: string): string {
  const item = asRecord(payload);
  const detail = item.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((entry) => asRecord(entry).msg)
      .filter((entry): entry is string => typeof entry === 'string');
    if (messages.length) return messages.join('; ');
  }
  return typeof item.message === 'string' ? item.message : fallback;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');

  let response: Response;
  try {
    response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError('The SentinelForge API is unreachable. Check that the backend is healthy.', 0);
  }

  const rawText = await response.text();
  let payload: unknown = undefined;
  if (rawText) {
    try {
      payload = JSON.parse(rawText) as unknown;
    } catch {
      payload = rawText;
    }
  }

  if (!response.ok) {
    throw new ApiError(
      errorMessage(payload, `Request failed with status ${response.status}.`),
      response.status,
      response.headers.get('x-request-id') || undefined,
    );
  }
  return payload as T;
}

function queryString(params: Record<string, string | number | undefined>): string {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '') query.set(key, String(value));
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : '';
}

export const api = {
  async health(signal?: AbortSignal): Promise<HealthStatus> {
    return adaptHealth(await request<unknown>('/health', { signal }));
  },

  async sensors(signal?: AbortSignal): Promise<Sensor[]> {
    const payload = await request<unknown>(`${API_BASE}/sensors`, { signal });
    return unwrapList(payload, ['sensors']).map(adaptSensor);
  },

  async events(signal?: AbortSignal, limit = 100): Promise<EventRecord[]> {
    const payload = await request<unknown>(`${API_BASE}/events${queryString({ limit })}`, { signal });
    return unwrapList(payload, ['events']).map(adaptEvent);
  },

  async alerts(signal?: AbortSignal): Promise<Alert[]> {
    const payload = await request<unknown>(`${API_BASE}/alerts`, { signal });
    return unwrapList(payload, ['alerts']).map(adaptAlert);
  },

  async alert(id: string, signal?: AbortSignal): Promise<Alert> {
    return adaptAlert(await request<unknown>(`${API_BASE}/alerts/${encodeURIComponent(id)}`, { signal }));
  },

  async rules(signal?: AbortSignal): Promise<DetectionRule[]> {
    const payload = await request<unknown>(`${API_BASE}/rules`, { signal });
    return unwrapList(payload, ['rules']).map(adaptRule);
  },

  async scenarios(signal?: AbortSignal): Promise<Scenario[]> {
    const payload = await request<unknown>(`${API_BASE}/scenarios`, { signal });
    return unwrapList(payload, ['scenarios']).map(adaptScenario);
  },

  async runScenario(id: string, dryRun: boolean, adminKey: string, sensorId?: string): Promise<ScenarioRun> {
    if (!adminKey) throw new ApiError('An admin key is required for scenario mutations.', 401);
    const payload = await request<unknown>(`${API_BASE}/scenarios/${encodeURIComponent(id)}/runs`, {
      method: 'POST',
      headers: { 'X-Admin-Key': adminKey },
      body: JSON.stringify({ dry_run: dryRun, ...(dryRun ? {} : { sensor_id: sensorId }) }),
    });
    return adaptRun(payload);
  },

  async seedDemo(seed: number, adminKey: string): Promise<{ message: string; detail: unknown }> {
    if (!adminKey) throw new ApiError('An admin key is required to seed demo data.', 401);
    const payload = await request<unknown>(`${API_BASE}/demo/seed`, {
      method: 'POST',
      headers: { 'X-Admin-Key': adminKey },
      body: JSON.stringify({ seed }),
    });
    const item = asRecord(payload);
    return {
      message: typeof item.message === 'string' ? item.message : `Demo dataset seeded with ${seed}.`,
      detail: payload,
    };
  },

  async coverage(signal?: AbortSignal): Promise<CoverageSummary> {
    return adaptCoverage(await request<unknown>(`${API_BASE}/attack/coverage`, { signal }));
  },

  async timeline(signal?: AbortSignal, limit = 1000): Promise<TimelineGraph> {
    return adaptTimeline(
      await request<unknown>(`${API_BASE}/timeline${queryString({ limit })}`, { signal }),
    );
  },
};

export function liveWebSocketUrl(): string | undefined {
  if (import.meta.env.VITE_LIVE_URL) return import.meta.env.VITE_LIVE_URL;
  if (typeof window === 'undefined' || !('WebSocket' in window)) return undefined;
  if (/^https?:\/\//.test(API_BASE)) {
    return `${API_BASE.replace(/^http/, 'ws')}/live`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}${API_BASE}/live`;
}
