import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/useAuth';
import { hasRole } from '../utils/permissions';

export default function ProtectedRoute({ children, allowedRoles = null }) {
  const { isAuthenticated, user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return <div className="page-shell"><div className="loading-panel">Loading session…</div></div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  if (allowedRoles && !allowedRoles.some((role) => hasRole(user, role))) {
    return (
      <div className="page-shell">
        <div className="message-card error">
          You are not authorized to access this page.
        </div>
      </div>
    );
  }

  return children;
}

export function RequireRole({ roles, children }) {
  const { user } = useAuth();

  if (!roles.some((role) => hasRole(user, role))) {
    return <div className="message-card error">Access denied.</div>;
  }

  return children;
}
