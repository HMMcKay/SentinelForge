import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { LoadingState } from './components/Status';

const OverviewPage = lazy(() => import('./pages/OverviewPage'));
const AlertsPage = lazy(() => import('./pages/AlertsPage'));
const TimelinePage = lazy(() => import('./pages/TimelinePage'));
const RulesPage = lazy(() => import('./pages/RulesPage'));
const ScenariosPage = lazy(() => import('./pages/ScenariosPage'));
const AttackPage = lazy(() => import('./pages/AttackPage'));
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'));

export default function App() {
  return (
    <Suspense fallback={<div className="route-loading"><LoadingState label="Opening workspace" /></div>}>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="alerts/:alertId" element={<AlertsPage />} />
          <Route path="timeline" element={<TimelinePage />} />
          <Route path="rules" element={<RulesPage />} />
          <Route path="scenarios" element={<ScenariosPage />} />
          <Route path="attack" element={<AttackPage />} />
          <Route path="home" element={<Navigate replace to="/" />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
