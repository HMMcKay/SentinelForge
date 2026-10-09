import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { api } from '../api/client';
import { useLive } from '../context/LiveContext';
import { useApiQuery } from '../hooks/useApiQuery';
import { relativeTime, titleCase } from '../utils/format';
import { Icon, type IconName } from './Icon';

const navigation: Array<{ to: string; label: string; icon: IconName; end?: boolean }> = [
  { to: '/', label: 'Overview', icon: 'activity', end: true },
  { to: '/alerts', label: 'Alert triage', icon: 'alert' },
  { to: '/timeline', label: 'Forensic timeline', icon: 'graph' },
  { to: '/rules', label: 'Detection rules', icon: 'rules' },
  { to: '/scenarios', label: 'Scenarios', icon: 'scenario' },
  { to: '/attack', label: 'ATT&CK coverage', icon: 'attack' },
];

export function AppShell() {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const health = useApiQuery(api.health, false);
  const live = useLive();

  useEffect(() => {
    setMenuOpen(false);
    const match = navigation.find((item) => item.to === location.pathname);
    document.title = match ? `${match.label} · SentinelForge` : 'SentinelForge';
  }, [location.pathname]);

  const liveLabel = live.status === 'connected'
    ? 'Live feed connected'
    : live.status === 'connecting'
      ? 'Connecting live feed'
      : live.status === 'unsupported'
        ? 'Live feed unavailable'
        : `Live feed reconnecting${live.reconnectAttempt ? ` (${live.reconnectAttempt})` : ''}`;

  return (
    <div className="app-shell">
      <aside className={`sidebar${menuOpen ? ' sidebar--open' : ''}`} aria-label="Primary navigation">
        <div className="brand">
          <span className="brand__mark"><Icon name="shield" size={24} /></span>
          <div>
            <strong>SentinelForge</strong>
            <span>Detection workbench</span>
          </div>
          <button className="icon-button sidebar__close" aria-label="Close navigation" onClick={() => setMenuOpen(false)} type="button">
            <Icon name="close" />
          </button>
        </div>

        <nav className="nav-list">
          <span className="nav-list__label">Workspace</span>
          {navigation.map((item) => (
            <NavLink
              className={({ isActive }) => `nav-link${isActive ? ' nav-link--active' : ''}`}
              end={item.end}
              key={item.to}
              to={item.to}
            >
              <Icon name={item.icon} size={19} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar__footer">
          <div className="environment-card">
            <div className="environment-card__title">
              <Icon name="database" size={16} />
              <span>Local environment</span>
            </div>
            <div className="environment-card__row">
              <span>API</span>
              <strong className={health.error ? 'text-danger' : ''}>
                {health.loading ? 'Checking' : health.error ? 'Unavailable' : titleCase(health.data?.status || 'Unknown')}
              </strong>
            </div>
            <div className="environment-card__row">
              <span>Lab mode</span>
              <strong className={health.data?.labMode ? 'text-warning' : ''}>
                {health.data?.labMode === undefined ? 'Unknown' : health.data.labMode ? 'Enabled' : 'Disabled'}
              </strong>
            </div>
          </div>
          <p>Defensive lab use only</p>
        </div>
      </aside>

      {menuOpen ? <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setMenuOpen(false)} type="button" /> : null}

      <div className="workspace">
        <header className="topbar">
          <button className="icon-button topbar__menu" aria-label="Open navigation" onClick={() => setMenuOpen(true)} type="button">
            <Icon name="menu" />
          </button>
          <div className="topbar__context">
            <span className="topbar__label">Isolated lab</span>
            <span className="topbar__separator" />
            <span>Local telemetry</span>
          </div>
          <div className="topbar__status" title={liveLabel}>
            <span className={`live-dot live-dot--${live.status}`} aria-hidden="true" />
            <span>{liveLabel}</span>
            {live.lastMessage ? <small>{relativeTime(live.lastMessage.timestamp)}</small> : null}
          </div>
        </header>

        <main className="content" id="main-content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
