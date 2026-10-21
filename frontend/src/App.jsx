import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { useCallback, useEffect, useState } from 'react';
import { AuthProvider } from './auth/AuthContext.jsx';
import { useAuth } from './auth/useAuth';
import { organizationApi, scanApi } from './api/client';
import LoadingSpinner from './components/LoadingSpinner';
import AppLayout from './layouts/AppLayout';
import LoginPage from './pages/auth/LoginPage';
import RegisterPage from './pages/auth/RegisterPage';
import ForgotPasswordPage from './pages/auth/ForgotPasswordPage';
import ResetPasswordPage from './pages/auth/ResetPasswordPage';
import OrganizationApprovalPage from './pages/super-admin/OrganizationApprovalPage';
import AnalystApprovalPage from './pages/admin/AnalystApprovalPage';
import ScanApprovalPage from './pages/admin/ScanApprovalPage';
import TargetManagementPage from './pages/admin/TargetManagementPage';
import AnalystWorkspacePage from './pages/analyst/AnalystWorkspacePage';
import ScanDetailsPage from './pages/analyst/ScanDetailsPage';
import ProtectedRoute from './routes/ProtectedRoute';
import { getRoleLabel } from './utils/permissions';
import { hasRole } from './utils/permissions';
import './styles/globals.css';

function dataOf(response) {
  return response?.data ?? response;
}

function metricLabel(value) {
  return String(value || '').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/_/g, ' ');
}

function DashboardOverview() {
  const { user } = useAuth();
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const role = hasRole(user, 'SUPER_ADMIN')
    ? 'SUPER_ADMIN'
    : hasRole(user, 'ADMIN')
      ? 'ADMIN'
      : hasRole(user, 'SECURITY_ANALYST') ? 'SECURITY_ANALYST' : null;

  const loadDashboard = useCallback(async () => {
    if (!role) {
      setDashboard(null);
      setError('Your authenticated account does not have a recognized application role.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const result = role === 'SUPER_ADMIN'
        ? await organizationApi.getPlatformDashboard()
        : role === 'ADMIN'
          ? await organizationApi.getDashboard()
          : await scanApi.getAnalystDashboard();
      setDashboard(dataOf(result) || {});
    } catch (requestError) {
      setError(requestError.message || 'Unable to load dashboard statistics.');
    } finally {
      setLoading(false);
    }
  }, [role]);

  useEffect(() => {
    void Promise.resolve().then(loadDashboard);
  }, [loadDashboard]);

  const metrics = role === 'SUPER_ADMIN'
    ? [
      ['Total organizations', dashboard?.totalOrganizations],
      ['Pending organizations', dashboard?.pendingOrganizations],
      ['Approved organizations', dashboard?.approvedOrganizations],
      ['Rejected organizations', dashboard?.rejectedOrganizations],
      ['Suspended organizations', dashboard?.suspendedOrganizations],
    ]
    : role === 'ADMIN'
      ? [
        ['Total targets', dashboard?.totalTargets],
        ['Approved targets', dashboard?.approvedTargets],
        ['Pending scan approvals', dashboard?.pendingScanApprovals],
        ['Queued scans', dashboard?.queuedScans],
        ['Running scans', dashboard?.runningScans],
        ['Completed scans', dashboard?.completedScans],
        ['Failed scans', dashboard?.failedScans],
        ['High severity findings', dashboard?.highSeverityFindings],
        ['Medium severity findings', dashboard?.mediumSeverityFindings],
        ['Low severity findings', dashboard?.lowSeverityFindings],
      ]
      : [
        ['Approved targets', dashboard?.approvedTargets],
        ['Pending scan approvals', dashboard?.pendingScanApprovals],
        ['Queued scans', dashboard?.queuedScans],
        ['Crawling scans', dashboard?.crawlingScans],
        ['Scanning scans', dashboard?.scanningScans],
        ['Running scans', dashboard?.runningScans],
        ['Completed scans', dashboard?.completedScans],
        ['Failed scans', dashboard?.failedScans],
        ['High severity findings', dashboard?.highSeverityFindings],
        ['Medium severity findings', dashboard?.mediumSeverityFindings],
        ['Low severity findings', dashboard?.lowSeverityFindings],
      ];

  return (
    <section className="page-shell">
      <div className="page-header">
        <div>
          <p className="eyebrow">Overview</p>
          <h1>{role === 'SUPER_ADMIN' ? 'Platform overview' : role === 'ADMIN' ? 'Organization overview' : 'Analyst overview'}</h1>
        </div>
        <button type="button" className="secondary-button" onClick={loadDashboard} disabled={loading}>Refresh</button>
      </div>

      <article className="data-card">
        <h3>Current role</h3>
        <p className="muted">{(user?.roles || []).map(getRoleLabel).join(', ') || 'No role assigned'}</p>
      </article>
      <article className="data-card">
        <h3>Organization scope</h3>
        <p className="muted">{user?.organization?.name || user?.organizationName || user?.organizationId || 'Not assigned'}</p>
      </article>
      {error ? (
        <div className="message-card error" role="alert">
          <p>{error}</p>
          <button type="button" className="secondary-button" onClick={loadDashboard}>Retry dashboard</button>
        </div>
      ) : loading ? <LoadingSpinner label="Loading dashboard statistics…" /> : (
        <div className="card-grid">
          {metrics.map(([label, value]) => (
            <article className="stat-card" key={label}>
              <span className="eyebrow">{metricLabel(label)}</span>
              <strong>{value ?? 'Unavailable'}</strong>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function AuthenticationRouter() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<DashboardOverview />} />
        <Route
          path="/super-admin/organizations"
          element={
            <ProtectedRoute allowedRoles={['SUPER_ADMIN']}>
              <OrganizationApprovalPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/targets"
          element={
            <ProtectedRoute allowedRoles={['ADMIN']}>
              <TargetManagementPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/analysts"
          element={
            <ProtectedRoute allowedRoles={['ADMIN']}>
              <AnalystApprovalPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/scans"
          element={
            <ProtectedRoute allowedRoles={['ADMIN']}>
              <ScanApprovalPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/analyst/workspace"
          element={
            <ProtectedRoute allowedRoles={['SECURITY_ANALYST']}>
              <AnalystWorkspacePage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/analyst/scans/:scanId"
          element={
            <ProtectedRoute allowedRoles={['SECURITY_ANALYST']}>
              <ScanDetailsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/scans/:scanId"
          element={
            <ProtectedRoute allowedRoles={['ADMIN']}>
              <ScanDetailsPage />
            </ProtectedRoute>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AuthenticationRouter />
      </AuthProvider>
    </BrowserRouter>
  );
}
