import { useEffect } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/useAuth';
import { getRoleLabel, hasRole } from '../utils/permissions';

function isNavLinkActive(link, location) {
  if (link.hash) {
    return location.pathname === '/analyst/workspace' && location.hash === link.hash;
  }
  if (link.exact) {
    return location.pathname === link.to && !location.hash;
  }
  return location.pathname === link.to || location.pathname.startsWith(`${link.to}/`);
}

function displayName(user) {
  return user?.displayName || user?.fullName || user?.name ||
    [user?.firstName, user?.lastName].filter(Boolean).join(' ') || 'Name unavailable';
}

export default function AppLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const navLinks = [
    { label: 'Overview', to: '/', exact: true },
  ];

  if (hasRole(user, 'SUPER_ADMIN')) {
    navLinks.push({ label: 'Organization approvals', to: '/super-admin/organizations' });
  }

  if (hasRole(user, 'ADMIN')) {
    navLinks.push({ label: 'Target management', to: '/admin/targets' });
    navLinks.push({ label: 'Analyst approvals', to: '/admin/analysts' });
    navLinks.push({ label: 'Scan approvals', to: '/admin/scans' });
  }

  if (hasRole(user, 'SECURITY_ANALYST')) {
    navLinks.push({ label: 'Analyst workspace', to: '/analyst/workspace', exact: true });
    navLinks.push({ label: 'Approved targets', to: '/analyst/workspace#targets', hash: '#targets' });
    navLinks.push({ label: 'Request scan', to: '/analyst/workspace#request-scan', hash: '#request-scan' });
    navLinks.push({ label: 'Scan history', to: '/analyst/workspace#history', hash: '#history' });
    navLinks.push({ label: 'Findings', to: '/analyst/workspace#findings', hash: '#findings' });
  }

  useEffect(() => {
    if (!location.hash) return;
    document.getElementById(location.hash.slice(1))?.scrollIntoView?.({ block: 'start' });
  }, [location.hash, location.pathname]);

  const handleLogout = async () => {
    try {
      await logout();
      navigate('/login', { replace: true });
    } catch (requestError) {
      navigate('/login', {
        replace: true,
        state: { logoutError: requestError.message || 'The server could not complete logout.' },
      });
    }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-mark brand-mark--small" aria-hidden="true">S</span>
          <div>
            <p className="eyebrow">Scanner Console</p>
            <h1>Secure Access</h1>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label="Main navigation">
          {navLinks.map((link) => {
            const active = isNavLinkActive(link, location);
            return (
              <Link
                key={link.to}
                to={link.to}
                className={`nav-link ${active ? 'active' : ''}`}
                aria-current={active ? 'page' : undefined}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>
      </aside>

      <main className="content-panel">
        <header className="topbar">
          <div>
            <p className="eyebrow">Authenticated</p>
            <h2>{displayName(user)}</h2>
          </div>
          <div className="topbar-actions">
            <span className="user-badge">{(user?.roles || []).map(getRoleLabel).join(', ') || 'No role'}</span>
            <button type="button" className="secondary-button" onClick={handleLogout}>
              Logout
            </button>
          </div>
        </header>

        <Outlet />
      </main>
    </div>
  );
}
