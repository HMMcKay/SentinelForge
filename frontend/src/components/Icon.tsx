export type IconName =
  | 'activity'
  | 'alert'
  | 'attack'
  | 'check'
  | 'chevron'
  | 'clock'
  | 'close'
  | 'database'
  | 'external'
  | 'filter'
  | 'graph'
  | 'host'
  | 'info'
  | 'menu'
  | 'pause'
  | 'play'
  | 'refresh'
  | 'rules'
  | 'scenario'
  | 'search'
  | 'sensor'
  | 'shield'
  | 'spark'
  | 'warning'
  | 'zoom-in'
  | 'zoom-out';

const paths: Record<IconName, React.ReactNode> = {
  activity: <><path d="M3 12h4l3-8 4 16 3-8h4" /></>,
  alert: <><path d="M12 9v4" /><path d="M12 17h.01" /><path d="M10.3 3.8 2.5 18a2 2 0 0 0 1.8 3h15.4a2 2 0 0 0 1.8-3L13.7 3.8a2 2 0 0 0-3.4 0Z" /></>,
  attack: <><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4" /><path d="M12 3v3M12 18v3M3 12h3M18 12h3" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  chevron: <path d="m9 18 6-6-6-6" />,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  close: <><path d="m6 6 12 12" /><path d="M18 6 6 18" /></>,
  database: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5" /><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" /></>,
  external: <><path d="M14 4h6v6" /><path d="m20 4-9 9" /><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6" /></>,
  filter: <path d="M4 5h16l-6 7v6l-4 2v-8L4 5Z" />,
  graph: <><circle cx="5" cy="6" r="2" /><circle cx="19" cy="5" r="2" /><circle cx="8" cy="19" r="2" /><circle cx="18" cy="17" r="2" /><path d="m7 6 10-.8M6 8l1.4 9M10 18l6-1M18 7l-.2 8" /></>,
  host: <><rect x="3" y="4" width="18" height="13" rx="2" /><path d="M8 21h8M12 17v4" /></>,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v6M12 7h.01" /></>,
  menu: <><path d="M4 7h16M4 12h16M4 17h16" /></>,
  pause: <><path d="M9 7v10M15 7v10" /></>,
  play: <path d="m9 7 8 5-8 5V7Z" />,
  refresh: <><path d="M20 7v5h-5" /><path d="M4 17v-5h5" /><path d="M6.1 8A7 7 0 0 1 18.4 6L20 8M4 16l1.6 2A7 7 0 0 0 18 16" /></>,
  rules: <><path d="M8 6h13M8 12h13M8 18h13" /><path d="m3 6 1 1 2-2M3 12l1 1 2-2M3 18l1 1 2-2" /></>,
  scenario: <><path d="M8 5v14l11-7L8 5Z" /><circle cx="12" cy="12" r="10" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
  sensor: <><path d="M8.5 8.5a5 5 0 0 1 7 0M5.5 5.5a9 9 0 0 1 13 0M12 12h.01" /><path d="M12 12v8" /></>,
  shield: <path d="M12 3 20 7v5c0 5-3.3 8.4-8 10-4.7-1.6-8-5-8-10V7l8-4Z" />,
  spark: <path d="m12 2 1.5 6.5L20 10l-6.5 1.5L12 18l-1.5-6.5L4 10l6.5-1.5L12 2Z" />,
  warning: <><path d="M12 9v4" /><path d="M12 17h.01" /><path d="M10.3 3.8 2.5 18a2 2 0 0 0 1.8 3h15.4a2 2 0 0 0 1.8-3L13.7 3.8a2 2 0 0 0-3.4 0Z" /></>,
  'zoom-in': <><circle cx="10" cy="10" r="6" /><path d="m15 15 5 5M10 7v6M7 10h6" /></>,
  'zoom-out': <><circle cx="10" cy="10" r="6" /><path d="m15 15 5 5M7 10h6" /></>,
};

export function Icon({ name, size = 20, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      height={size}
      viewBox="0 0 24 24"
      width={size}
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.8"
    >
      {paths[name]}
    </svg>
  );
}
