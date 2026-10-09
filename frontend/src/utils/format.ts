import type { Severity } from '../types';

export function formatDateTime(value?: string): string {
  if (!value) return 'Not available';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(date);
}

export function formatTime(value?: string): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date);
}

export function relativeTime(value?: string, now = Date.now()): string {
  if (!value) return 'never';
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) return value;
  const seconds = Math.round((timestamp - now) / 1000);
  const absolute = Math.abs(seconds);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  if (absolute < 60) return formatter.format(seconds, 'second');
  if (absolute < 3600) return formatter.format(Math.round(seconds / 60), 'minute');
  if (absolute < 86_400) return formatter.format(Math.round(seconds / 3600), 'hour');
  return formatter.format(Math.round(seconds / 86_400), 'day');
}

export function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function severityRank(value: Severity): number {
  return {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    informational: 1,
    unknown: 0,
  }[value];
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

export function compactId(value: string, size = 8): string {
  return value.length > size + 3 ? `${value.slice(0, size)}…` : value;
}
