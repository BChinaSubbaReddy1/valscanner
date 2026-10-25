import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from '../App';
import * as client from '../api/client';
import { canManageOrganizations, canManageTargets, canViewAnalystWorkspace, getRoleLabel, hasRole, getUserRoles } from '../utils/permissions';

function renderApp(route = '/login') {
  window.history.pushState({}, 'Test page', route);
  return render(<App />);
}

describe('Role and permission utilities', () => {
  it('identifies exact application roles and excludes non-existent roles', () => {
    const superAdmin = { roles: ['SUPER_ADMIN'] };
    const admin = { roles: ['ADMIN'] };
    const analyst = { roles: ['SECURITY_ANALYST'] };

    expect(canManageOrganizations(superAdmin)).toBe(true);
    expect(canManageOrganizations(admin)).toBe(false);
    expect(canManageOrganizations(analyst)).toBe(false);
    expect(hasRole(admin, 'ADMIN')).toBe(true);
    expect(getUserRoles(admin)).toEqual(['ADMIN']);

    expect(canManageTargets(admin)).toBe(true);
    expect(canManageTargets(superAdmin)).toBe(false);
    expect(canManageTargets(analyst)).toBe(false);

    expect(canViewAnalystWorkspace(analyst)).toBe(true);
    expect(canViewAnalystWorkspace(superAdmin)).toBe(false);

    expect(getRoleLabel('ADMIN')).toBe('Organization Admin');
    expect(getRoleLabel('CUSTOMER')).toBe('Unrecognized role');
  });
});

describe('Authentication, Access Control and IAM Views', () => {
  beforeEach(() => {
    localStorage.clear();
    window.history.pushState({}, 'Test page', '/login');
    vi.restoreAllMocks();
    vi.spyOn(client.authApi, 'currentUser').mockImplementation(async () => ({
      data: client.readStoredSession()?.user || {},
    }));
    vi.spyOn(client.organizationApi, 'getDashboard').mockResolvedValue({ data: {} });
    vi.spyOn(client.organizationApi, 'getPlatformDashboard').mockResolvedValue({ data: {} });
    vi.spyOn(client.scanApi, 'getAnalystDashboard').mockResolvedValue({ data: {} });
    vi.spyOn(client.scanApi, 'getReport').mockResolvedValue({ data: null });
  });

  it('validates required login inputs', async () => {
    renderApp();
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));
    expect(screen.getByText(/both email or username and password are required/i)).toBeInTheDocument();
  });

  it('logs in with the backend contract and loads the authenticated organization context', async () => {
    const loginSpy = vi.spyOn(client.authApi, 'login').mockResolvedValue({
      data: { token: 'authenticated-token', userId: 7, email: 'admin@example.com', roles: ['ADMIN'] },
    });
    const profileSpy = vi.spyOn(client.authApi, 'currentUser').mockResolvedValue({
      data: { id: 7, email: 'admin@example.com', organizationId: 12, roles: ['ADMIN'] },
    });

    renderApp('/login');
    await userEvent.type(screen.getByLabelText(/email or username/i), 'admin@example.com');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'LongPassword123');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(loginSpy).toHaveBeenCalledWith({
        email: 'admin@example.com',
        password: 'LongPassword123',
      });
      expect(profileSpy).toHaveBeenCalled();
      expect(screen.getByText('12')).toBeInTheDocument();
      expect(screen.getByText(/analyst approvals/i)).toBeInTheDocument();
    });
  });

  it('does not send a stored bearer token with public registration requests', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'expired-token',
      user: { roles: ['ADMIN'] },
    }));
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 201,
      headers: { get: () => 'application/json' },
      json: async () => ({ success: true, data: { email: 'admin@example.com' } }),
    });

    await client.authApi.register({
      firstName: 'Jordan',
      lastName: 'Admin',
      email: 'admin@example.com',
      password: 'LongPassword123',
      role: 'ADMIN',
      organizationName: 'Northstar',
    });

    expect(fetchSpy.mock.calls[0][1].headers.has('Authorization')).toBe(false);
    expect(localStorage.getItem('scanner-auth-session')).not.toBeNull();
  });

  it('uses backend organization and membership decision routes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ success: true, message: 'Completed', data: [] }),
    });

    await client.organizationApi.decideRegistration(12, 'REJECT');
    await client.organizationApi.listPendingMembershipRequests(12);
    await client.organizationApi.decideMembership(12, 44, 'APPROVE');

    expect(fetchSpy.mock.calls.map(([url]) => new URL(url).pathname)).toEqual([
      '/api/organizations/12/reject',
      '/api/organizations/12/membership-requests',
      '/api/organizations/12/membership-requests/44/approve',
    ]);
    expect(fetchSpy.mock.calls[0][1]).toMatchObject({ method: 'POST', body: '{}' });
  });

  it('uses authenticated self-scoped organization user endpoints and action payloads', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'admin-bearer-token',
      user: { roles: ['ADMIN'] },
    }));
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ success: true, message: 'Completed', data: {} }),
    });
    client.organizationApi.getDashboard.mockRestore();
    client.organizationApi.getPlatformDashboard.mockRestore();

    await client.organizationApi.getDashboard();
    await client.organizationApi.getPlatformDashboard();
    await client.organizationApi.listUsers({
      role: 'SECURITY_ANALYST',
      status: 'PENDING_APPROVAL',
      search: 'Casey Analyst',
      page: 2,
      size: 20,
    });
    await client.organizationApi.decideApproval(44, 'APPROVE');
    await client.organizationApi.updateUserStatus(45, 'suspend');
    await client.organizationApi.listOrganizationAdmins({ status: 'ACTIVE', page: 1, size: 10 });
    await client.organizationApi.updateOrganizationAdmin(46, 'deactivate');

    expect(fetchSpy.mock.calls.map(([url]) => new URL(url).pathname)).toEqual([
      '/api/organizations/me/dashboard',
      '/api/organizations/platform-dashboard',
      '/api/organizations/me/users',
      '/api/organizations/me/approval-requests/44/approve',
      '/api/organizations/me/users/45/suspend',
      '/api/organizations/admin-accounts',
      '/api/organizations/admin-accounts/46/deactivate',
    ]);
    const userListUrl = new URL(fetchSpy.mock.calls[2][0]);
    expect(Object.fromEntries(userListUrl.searchParams.entries())).toEqual({
      page: '2',
      size: '20',
      role: 'SECURITY_ANALYST',
      status: 'PENDING_APPROVAL',
      search: 'Casey Analyst',
    });
    expect(userListUrl.searchParams.has('organizationId')).toBe(false);
    expect(fetchSpy.mock.calls[0][1].headers.get('Authorization')).toBe('Bearer admin-bearer-token');
    expect(fetchSpy.mock.calls[3][1].body).toBe('{}');
    expect(fetchSpy.mock.calls[4][1].body).toBe('{}');
    expect(new URL(fetchSpy.mock.calls[5][0]).searchParams.get('status')).toBe('ACTIVE');
    expect(fetchSpy.mock.calls[6][1].body).toBe('{}');
  });

  it('uses the implemented target routes and backend request fields', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ success: true, message: 'Completed', data: [] }),
    });

    await client.targetApi.listTargets();
    await client.targetApi.createTarget({
      name: 'Public app',
      url: 'https://example.org',
      type: 'WEB_APPLICATION',
    });
    await client.targetApi.decideTarget(51, 'APPROVE');
    await client.targetApi.decideTarget(52, 'REJECT');
    await client.targetApi.deleteTarget(51);

    expect(fetchSpy.mock.calls.map(([url]) => new URL(url).pathname)).toEqual([
      '/api/targets',
      '/api/targets',
      '/api/targets/51/decision',
      '/api/targets/52/decision',
      '/api/targets/51',
    ]);
    expect(fetchSpy.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'POST', 'POST', 'POST', 'DELETE']);
    expect(fetchSpy.mock.calls[1][1].body).toBe('{"name":"Public app","url":"https://example.org","type":"WEB_APPLICATION"}');
    expect(fetchSpy.mock.calls[2][1].body).toBe('{"decision":"APPROVE"}');
    expect(fetchSpy.mock.calls[3][1].body).toBe('{"decision":"REJECT"}');
  });

  it('uses the verified scanner routes, request contract, and bearer token', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'analyst-bearer-token',
      user: { roles: ['SECURITY_ANALYST'] },
    }));
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ success: true, data: { id: 81 } }),
    });
    client.scanApi.getAnalystDashboard.mockRestore();

    await client.scanApi.createScan(71, 'PASSIVE_HEADERS');
    await client.scanApi.listScans({ page: 1, size: 10 });
    await client.scanApi.getScan(81);
    await client.scanApi.cancelScan(81);
    await client.scanApi.listFindings(81);
    await client.scanApi.listCrawlPages(81);
    await client.scanApi.getAnalystDashboard();

    expect(fetchSpy.mock.calls.map(([url]) => new URL(url).pathname)).toEqual([
      '/api/scans',
      '/api/scans',
      '/api/scans/81',
      '/api/scans/81/cancel',
      '/api/scans/81/findings',
      '/api/scans/81/crawl-pages',
      '/api/scans/me/dashboard',
    ]);
    expect(fetchSpy.mock.calls.map(([, options]) => options.method)).toEqual([
      'POST', 'GET', 'GET', 'POST', 'GET', 'GET', 'GET',
    ]);
    expect(fetchSpy.mock.calls[0][1].body).toBe('{"targetId":71,"scanType":"PASSIVE_HEADERS"}');
    expect(fetchSpy.mock.calls.every(([, options]) =>
      /^Bearer .+/.test(options.headers.get('Authorization') || ''))).toBe(true);
    expect(new URL(fetchSpy.mock.calls[1][0]).searchParams.toString()).toBe('page=1&size=10');
  });

  it('submits supported ZAP scan modes and rejects unknown modes locally', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 201,
      headers: { get: () => 'application/json' },
      json: async () => ({ success: true, data: { id: 82 } }),
    });

    await client.scanApi.createScan(71, 'ZAP_ACTIVE');

    expect(fetchSpy.mock.calls[0][1].body).toBe('{"targetId":71,"scanType":"ZAP_ACTIVE"}');
    await expect(client.scanApi.createScan(71, 'UNSUPPORTED_MODE'))
      .rejects.toThrow('Unsupported scan type.');
    expect(fetchSpy).toHaveBeenCalledOnce();
  });

  it('uses the verified scan approval routes and requires rejection reasons', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'admin-bearer-token',
      user: { roles: ['ADMIN'] },
    }));
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ success: true, data: { content: [] } }),
    });

    await client.scanApi.listPendingApprovals({ page: 2, size: 20 });
    await client.scanApi.approveScan(81);
    await client.scanApi.rejectScan(81, 'Target is outside the approved review scope.');

    expect(fetchSpy.mock.calls.map(([url]) => new URL(url).pathname)).toEqual([
      '/api/scans/pending-approval',
      '/api/scans/81/approve',
      '/api/scans/81/reject',
    ]);
    expect(fetchSpy.mock.calls[0][1].method).toBe('GET');
    expect(fetchSpy.mock.calls[1][1].method).toBe('POST');
    expect(fetchSpy.mock.calls[2][1].body).toBe('{"reason":"Target is outside the approved review scope."}');
    await expect(client.scanApi.rejectScan(81, '   ')).rejects.toThrow(/rejection reason is required/i);
  });

  it('maps common backend failures to consistent actionable errors', async () => {
    const failures = [
      [400, /request was invalid/i],
      [401, /authentication failed/i],
      [403, /not authorized/i],
      [404, /resource was not found/i],
      [409, /conflicts with existing data/i],
      [503, /server could not complete/i],
    ];
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    for (const [status, message] of failures) {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status,
        headers: { get: () => 'application/json' },
        json: async () => ({}),
      });
      await expect(client.apiRequest('/api/test')).rejects.toMatchObject({
        status,
        message: expect.stringMatching(message),
      });
    }

    fetchSpy.mockRejectedValueOnce(new TypeError('connection reset details'));
    await expect(client.apiRequest('/api/test')).rejects.toThrow(
      'Network request failed. Check your connection and try again.',
    );
  });

  it('expires stored sessions on authenticated 401s and rejects unsuccessful envelopes', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'expired-token',
      user: { roles: ['ADMIN'] },
    }));
    const expiredListener = vi.fn();
    window.addEventListener('auth:session-expired', expiredListener);
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: false,
      status: 401,
      headers: { get: () => 'application/json' },
      json: async () => ({}),
    }).mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ success: false, message: 'Decision was not accepted.' }),
    });

    await expect(client.apiRequest('/api/test')).rejects.toMatchObject({
      status: 401,
      message: 'Your session has expired. Sign in again.',
    });
    expect(localStorage.getItem('scanner-auth-session')).toBeNull();
    expect(expiredListener).toHaveBeenCalledOnce();
    await expect(client.apiRequest('/api/test')).rejects.toMatchObject({
      status: 200,
      message: 'Decision was not accepted.',
    });

    window.removeEventListener('auth:session-expired', expiredListener);
  });

  it('clears the local session after logout', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-token',
      user: { roles: ['ADMIN'] },
    }));
    const logoutSpy = vi.spyOn(client.authApi, 'logout').mockResolvedValue({
      success: true,
      message: 'Logged out',
    });

    renderApp('/');
    await userEvent.click(screen.getByRole('button', { name: /logout/i }));

    await waitFor(() => {
      expect(logoutSpy).toHaveBeenCalled();
      expect(localStorage.getItem('scanner-auth-session')).toBeNull();
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
    });
  });

  it('submits a Security Analyst registration with an organization name and no unsupported fields', async () => {
    const registerSpy = vi.spyOn(client.authApi, 'register').mockResolvedValue({
      success: true,
      message: 'User registered',
      data: { email: 'analyst@example.com' },
    });

    renderApp('/register');
    await userEvent.type(screen.getByLabelText(/^first name$/i), 'Taylor');
    await userEvent.type(screen.getByLabelText(/^last name$/i), 'Security');
    await userEvent.type(screen.getByLabelText(/^email$/i), 'analyst@example.com');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'LongPassword123');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'LongPassword123');
    await userEvent.type(screen.getByLabelText(/^organization name$/i), 'Northstar');
    expect(screen.queryByLabelText(/organization id/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/invitation token/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /^register$/i }));

    await waitFor(() => {
      expect(registerSpy).toHaveBeenCalledWith({
        firstName: 'Taylor',
        lastName: 'Security',
        email: 'analyst@example.com',
        password: 'LongPassword123',
        role: 'SECURITY_ANALYST',
        organizationName: 'Northstar',
      });
      expect(screen.getByText(/membership is pending organization admin approval/i)).toBeInTheDocument();
    });
    const roleSelect = screen.getByRole('combobox', { name: /requested role/i });
    expect(roleSelect.querySelector('option[value="SUPER_ADMIN"]')).not.toBeInTheDocument();
    expect(roleSelect.querySelector('option[value="CUSTOMER"]')).not.toBeInTheDocument();
    expect(roleSelect.querySelectorAll('option')).toHaveLength(2);
  });

  it('accepts an eight-character registration password', async () => {
    const registerSpy = vi.spyOn(client.authApi, 'register').mockResolvedValue({
      success: true,
      message: 'User registered',
      data: { email: 'analyst@example.com' },
    });

    renderApp('/register');
    await userEvent.type(screen.getByLabelText(/^first name$/i), 'Taylor');
    await userEvent.type(screen.getByLabelText(/^last name$/i), 'Security');
    await userEvent.type(screen.getByLabelText(/^email$/i), 'analyst@example.com');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'Pass1234');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'Pass1234');
    await userEvent.type(screen.getByLabelText(/^organization name$/i), 'Northstar');
    await userEvent.click(screen.getByRole('button', { name: /^register$/i }));

    await waitFor(() => {
      expect(registerSpy).toHaveBeenCalledWith(expect.objectContaining({
        password: 'Pass1234',
        role: 'SECURITY_ANALYST',
        organizationName: 'Northstar',
      }));
      expect(registerSpy.mock.calls[0][0]).not.toHaveProperty('organizationId');
      expect(registerSpy.mock.calls[0][0]).not.toHaveProperty('invitationToken');
    });
  });

  it('prevents duplicate registration submissions while the request is pending', async () => {
    let finishRequest;
    const registerSpy = vi.spyOn(client.authApi, 'register').mockImplementation(() => new Promise((resolve) => {
      finishRequest = resolve;
    }));

    renderApp('/register');
    await userEvent.type(screen.getByLabelText(/^first name$/i), 'Taylor');
    await userEvent.type(screen.getByLabelText(/^last name$/i), 'Analyst');
    await userEvent.type(screen.getByLabelText(/^email$/i), 'analyst@example.com');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'LongPassword123');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'LongPassword123');
    await userEvent.type(screen.getByLabelText(/^organization name$/i), 'Northstar');
    const submit = screen.getByRole('button', { name: /^register$/i });
    await userEvent.click(submit);
    await waitFor(() => expect(registerSpy).toHaveBeenCalledOnce());

    expect(screen.getByRole('button', { name: /submitting/i })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: /submitting/i }));
    expect(registerSpy).toHaveBeenCalledOnce();
    await act(async () => {
      finishRequest({ success: true, message: 'User registered', data: { email: 'analyst@example.com' } });
    });
  });

  it('rejects registration passwords shorter than eight characters', async () => {
    const registerSpy = vi.spyOn(client.authApi, 'register');

    renderApp('/register');
    await userEvent.type(screen.getByLabelText(/^first name$/i), 'Taylor');
    await userEvent.type(screen.getByLabelText(/^last name$/i), 'Security');
    await userEvent.type(screen.getByLabelText(/^email$/i), 'analyst@example.com');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'Pass123');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'Pass123');
    await userEvent.click(screen.getByRole('button', { name: /^register$/i }));

    expect(screen.getByText(/password must be at least 8 characters/i)).toBeInTheDocument();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('submits Organization Admin registration with a new organization name', async () => {
    const registerSpy = vi.spyOn(client.authApi, 'register').mockResolvedValue({
      success: true,
      message: 'User registered',
      data: { email: 'admin@example.com' },
    });

    renderApp('/register');
    await userEvent.type(screen.getByLabelText(/^first name$/i), 'Jordan');
    await userEvent.type(screen.getByLabelText(/^last name$/i), 'Admin');
    await userEvent.type(screen.getByLabelText(/^email$/i), 'admin@example.com');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'LongPassword123');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'LongPassword123');
    await userEvent.selectOptions(screen.getByRole('combobox', { name: /requested role/i }), 'ADMIN');
    expect(screen.queryByLabelText(/organization id/i)).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/organization name/i), 'Northstar');
    await userEvent.type(screen.getByLabelText(/organization contact email/i), 'security@northstar.example');
    await userEvent.click(screen.getByRole('button', { name: /^register$/i }));

    await waitFor(() => {
      expect(registerSpy).toHaveBeenCalledWith({
        firstName: 'Jordan',
        lastName: 'Admin',
        email: 'admin@example.com',
        password: 'LongPassword123',
        role: 'ADMIN',
        organizationName: 'Northstar',
        organizationContactEmail: 'security@northstar.example',
      });
      expect(screen.getByText(/pending super admin approval/i)).toBeInTheDocument();
    });
  });

  it('shows registration validation errors returned by the backend', async () => {
    vi.spyOn(client.authApi, 'register').mockRejectedValue(
      Object.assign(new Error('Organization not found or not approved'), { status: 400 }),
    );

    renderApp('/register');
    await userEvent.type(screen.getByLabelText(/^first name$/i), 'Taylor');
    await userEvent.type(screen.getByLabelText(/^last name$/i), 'Analyst');
    await userEvent.type(screen.getByLabelText(/^email$/i), 'analyst@example.com');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'LongPassword123');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'LongPassword123');
    await userEvent.type(screen.getByLabelText(/^organization name$/i), 'Unapproved');
    await userEvent.click(screen.getByRole('button', { name: /^register$/i }));

    expect(await screen.findByText('Organization not found or not approved')).toBeInTheDocument();
    expect(screen.queryByText(/membership is pending organization admin approval/i)).not.toBeInTheDocument();
  });

  it('rejects an unsupported registration role before calling the API', async () => {
    const registerSpy = vi.spyOn(client.authApi, 'register');
    renderApp('/register');

    fireEvent.change(screen.getByRole('combobox', { name: /requested role/i }), {
      target: { value: 'SUPER_ADMIN' },
    });
    await userEvent.type(screen.getByLabelText(/^first name$/i), 'Taylor');
    await userEvent.type(screen.getByLabelText(/^last name$/i), 'Admin');
    await userEvent.type(screen.getByLabelText(/^email$/i), 'unsupported@example.com');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'LongPassword123');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'LongPassword123');
    await userEvent.type(screen.getByLabelText(/^organization name$/i), 'Northstar');
    await userEvent.click(screen.getByRole('button', { name: /^register$/i }));

    expect(screen.getByText(/select a supported registration role/i)).toBeInTheDocument();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('redirects unauthenticated users to login', () => {
    renderApp('/super-admin/organizations');
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('blocks Organization Admins from the Super Admin organizations route', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-admin-token',
      user: { roles: ['ADMIN'] },
    }));
    const pendingOrganizationsSpy = vi.spyOn(client.organizationApi, 'listPendingRegistrations');

    renderApp('/super-admin/organizations');

    expect(await screen.findByText(/not authorized to access this page/i)).toBeInTheDocument();
    expect(pendingOrganizationsSpy).not.toHaveBeenCalled();
  });

  it('blocks Security Analysts from Organization Admin target management', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: { roles: ['SECURITY_ANALYST'] },
    }));
    const targetListSpy = vi.spyOn(client.targetApi, 'listTargets');

    renderApp('/admin/targets');

    expect(await screen.findByText(/not authorized to access this page/i)).toBeInTheDocument();
    expect(targetListSpy).not.toHaveBeenCalled();
  });

  it('handles navigation and dashboard for ADMIN', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-admin-token',
      user: { username: 'admin-user', email: 'admin@company.com', roles: ['ADMIN'] },
    }));

    renderApp('/');
    await waitFor(() => {
      expect(screen.getByText(/target management/i)).toBeInTheDocument();
      expect(screen.getByText(/analyst approvals/i)).toBeInTheDocument();
      expect(screen.queryByText(/organization approvals/i)).not.toBeInTheDocument();
    });
  });

  it('handles navigation and dashboard for SUPER_ADMIN', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-super-token',
      user: { username: 'super-admin', email: 'super@company.com', roles: ['SUPER_ADMIN'] },
    }));

    renderApp('/');
    await waitFor(() => {
      expect(screen.getByText(/organization approvals/i)).toBeInTheDocument();
      expect(screen.queryByText(/target management/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/analyst workspace/i)).not.toBeInTheDocument();
    });
  });

  it('handles navigation and dashboard for SECURITY_ANALYST', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: { username: 'analyst-user', email: 'analyst@company.com', roles: ['SECURITY_ANALYST'] },
    }));

    renderApp('/');
    await waitFor(() => {
      expect(screen.getByText(/analyst workspace/i)).toBeInTheDocument();
      expect(screen.queryByText(/organization approvals/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/target management/i)).not.toBeInTheDocument();
    });
  });

  it('renders the verified role-scoped dashboard aggregates', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-admin-token',
      user: { roles: ['ADMIN'], organizationId: 12 },
    }));
    const adminDashboardSpy = vi.spyOn(client.organizationApi, 'getDashboard').mockResolvedValue({
      data: {
        totalTargets: 8,
        approvedTargets: 6,
        pendingScanApprovals: 2,
        highSeverityFindings: 3,
      },
    });

    renderApp('/');

    expect(await screen.findByText('8')).toBeInTheDocument();
    expect(screen.getByText(/high severity findings/i)).toBeInTheDocument();
    expect(adminDashboardSpy).toHaveBeenCalledTimes(1);
  });

  it('uses separate platform and analyst dashboard contracts by role', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-super-token',
      user: { roles: ['SUPER_ADMIN'] },
    }));
    const platformDashboardSpy = vi.spyOn(client.organizationApi, 'getPlatformDashboard').mockResolvedValue({
      data: { totalOrganizations: 11, pendingOrganizations: 2, approvedOrganizations: 8 },
    });

    renderApp('/');

    expect(await screen.findByText('11')).toBeInTheDocument();
    expect(screen.getByText(/pending organizations/i)).toBeInTheDocument();
    expect(platformDashboardSpy).toHaveBeenCalledTimes(1);

    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: { roles: ['SECURITY_ANALYST'] },
    }));
    const analystDashboardSpy = vi.spyOn(client.scanApi, 'getAnalystDashboard').mockResolvedValue({
      data: { approvedTargets: 4, crawlingScans: 1, highSeverityFindings: 2 },
    });

    renderApp('/');

    expect(await screen.findByText('4')).toBeInTheDocument();
    expect(screen.getByText(/crawling scans/i)).toBeInTheDocument();
    expect(analystDashboardSpy).toHaveBeenCalledTimes(1);
  });

  it('shows authorized targets and scan controls only for an active approved analyst', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        username: 'analyst-user',
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    const targetsSpy = vi.spyOn(client.targetApi, 'listTargets').mockResolvedValue({
      data: [{
        id: 71,
        name: 'Approved portal',
        url: 'https://portal.example.test',
        type: 'WEB_APPLICATION',
        status: 'APPROVED',
      }],
    });
    vi.spyOn(client.scanApi, 'listScans').mockResolvedValue({
      data: { content: [], totalPages: 0, totalElements: 0, number: 0 },
    });

    renderApp('/analyst/workspace');

    expect(await screen.findByRole('heading', { name: 'Approved portal' })).toBeInTheDocument();
    expect(targetsSpy).toHaveBeenCalled();
    expect(await screen.findByRole('button', { name: /run scan/i })).toBeEnabled();
    expect(screen.getByText(/no scan jobs were returned/i)).toBeInTheDocument();
  });

  it('shows organization-scoped pending scan requests with backend approval controls', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-admin-token',
      user: { roles: ['ADMIN'], accountStatus: 'ACTIVE', organizationStatus: 'APPROVED' },
    }));
    const pendingApprovalsSpy = vi.spyOn(client.scanApi, 'listPendingApprovals').mockResolvedValue({
      data: {
        content: [{
          id: 101,
          targetId: 71,
          targetName: 'Approved portal',
          scanType: 'PASSIVE_HEADERS',
          status: 'PENDING_APPROVAL',
          createdAt: '2026-10-20T10:00:00Z',
          statusMessage: 'Awaiting Organization Admin approval',
        }],
        totalPages: 1,
        totalElements: 1,
        number: 0,
      },
    });

    renderApp('/admin/scans');

    expect(await screen.findByRole('heading', { name: 'Scan approvals' })).toBeInTheDocument();
    expect(screen.getByText('Approved portal')).toBeInTheDocument();
    expect(screen.getByText('PENDING APPROVAL')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approve' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeEnabled();
    expect(pendingApprovalsSpy).toHaveBeenCalledWith({ page: 0, size: 20 });
  });

  it('does not load targets or expose scan controls without account and membership approval', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'pending-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'PENDING_APPROVAL',
        membershipApprovalStatus: 'PENDING_APPROVAL',
        organizationStatus: 'APPROVED',
      },
    }));
    const targetsSpy = vi.spyOn(client.targetApi, 'listTargets');
    const scansSpy = vi.spyOn(client.scanApi, 'listScans');

    renderApp('/analyst/workspace');

    expect(await screen.findByText(/scan access requires an active account/i)).toBeInTheDocument();
    expect(targetsSpy).not.toHaveBeenCalled();
    expect(scansSpy).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /run scan/i })).not.toBeInTheDocument();
  });

  it('starts an approved-target scan once and refreshes history from the API', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    const created = {
      id: 82,
      targetId: 71,
      targetName: 'Approved portal',
      scanType: 'PASSIVE_HEADERS',
      status: 'CREATED',
      progress: 0,
      statusMessage: 'Awaiting passive scanner availability',
      createdAt: '2026-10-20T10:00:00Z',
    };
    let jobs = [];
    vi.spyOn(client.targetApi, 'listTargets').mockResolvedValue({
      data: [{ id: 71, name: 'Approved portal', url: 'https://portal.example.test', status: 'APPROVED' }],
    });
    const listScansSpy = vi.spyOn(client.scanApi, 'listScans').mockImplementation(async () => ({
      data: { content: jobs, totalPages: 1, totalElements: jobs.length, number: 0 },
    }));
    let resolveCreate;
    const createScanSpy = vi.spyOn(client.scanApi, 'createScan').mockImplementation(() => new Promise((resolve) => {
      resolveCreate = resolve;
    }));

    renderApp('/analyst/workspace');
    const runButton = await screen.findByRole('button', { name: /run scan/i });
    await userEvent.click(runButton);
    await waitFor(() => expect(createScanSpy).toHaveBeenCalledOnce());
    expect(createScanSpy).toHaveBeenCalledWith(71, 'PASSIVE_HEADERS');
    expect(runButton).toBeDisabled();

    jobs = [created];
    await act(async () => {
      resolveCreate({ message: 'Scan job created', data: created });
    });

    expect(await screen.findByRole('status')).toHaveTextContent('Scan job created');
    expect(await screen.findAllByRole('heading', { name: 'Approved portal' })).toHaveLength(2);
    expect(screen.getByText('CREATED')).toBeInTheDocument();
    expect(listScansSpy).toHaveBeenCalled();
  });

  it('allows an analyst to request ZAP active scanning with admin approval clearly stated', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    vi.spyOn(client.targetApi, 'listTargets').mockResolvedValue({
      data: [{ id: 71, name: 'Authorized lab', url: 'http://lab.example.test', status: 'APPROVED' }],
    });
    vi.spyOn(client.scanApi, 'listScans').mockResolvedValue({
      data: { content: [], totalPages: 0, totalElements: 0, number: 0 },
    });
    const createScanSpy = vi.spyOn(client.scanApi, 'createScan').mockResolvedValue({
      message: 'Scan request submitted',
      data: { id: 83, targetId: 71, targetName: 'Authorized lab', scanType: 'ZAP_ACTIVE', status: 'PENDING_APPROVAL' },
    });

    renderApp('/analyst/workspace');
    await userEvent.selectOptions(await screen.findByRole('combobox', { name: /scan type/i }), 'ZAP_ACTIVE');
    expect(screen.getByRole('note')).toHaveTextContent(/active scanning sends test requests/i);
    expect(screen.getByRole('note')).toHaveTextContent(/organization admin approval/i);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: /approved target/i }), '71');
    await userEvent.click(screen.getByRole('button', { name: /start selected scan/i }));

    await waitFor(() => expect(createScanSpy).toHaveBeenCalledWith(71, 'ZAP_ACTIVE'));
    expect(await screen.findByRole('status')).toHaveTextContent('Scan request submitted');
  });

  it('shows authorization failures when a scan cannot be started', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    vi.spyOn(client.targetApi, 'listTargets').mockResolvedValue({
      data: [{ id: 71, name: 'Approved portal', status: 'APPROVED' }],
    });
    vi.spyOn(client.scanApi, 'listScans').mockResolvedValue({
      data: { content: [], totalPages: 0, totalElements: 0, number: 0 },
    });
    const createScanSpy = vi.spyOn(client.scanApi, 'createScan').mockRejectedValue(
      Object.assign(new Error('You are not authorized to perform this action.'), { status: 403 }),
    );

    renderApp('/analyst/workspace');
    await userEvent.click(await screen.findByRole('button', { name: /run scan/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/not authorized/i);
    expect(createScanSpy).toHaveBeenCalledWith(71, 'PASSIVE_HEADERS');
    expect(screen.queryByText(/was created by the backend/i)).not.toBeInTheDocument();
  });

  it('renders backend scan statuses and only offers cancellation before execution', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    const jobs = [
      { id: 1, targetId: 71, targetName: 'Target A', scanType: 'PASSIVE_HEADERS', status: 'QUEUED', progress: 0 },
      { id: 2, targetId: 71, targetName: 'Target A', scanType: 'PASSIVE_HEADERS', status: 'RUNNING', progress: 45 },
      { id: 3, targetId: 71, targetName: 'Target A', scanType: 'PASSIVE_HEADERS', status: 'COMPLETED', progress: 100 },
      { id: 4, targetId: 71, targetName: 'Target A', scanType: 'PASSIVE_HEADERS', status: 'FAILED', progress: 25, failureReason: 'SCANNER_UNAVAILABLE' },
      { id: 5, targetId: 71, targetName: 'Target A', scanType: 'PASSIVE_HEADERS', status: 'CANCELLED', progress: 0 },
    ];
    vi.spyOn(client.targetApi, 'listTargets').mockResolvedValue({ data: [] });
    vi.spyOn(client.scanApi, 'listScans').mockResolvedValue({
      data: { content: jobs, totalPages: 1, totalElements: jobs.length, number: 0 },
    });
    vi.spyOn(client.scanApi, 'listFindings').mockResolvedValue({ data: [] });
    const cancelSpy = vi.spyOn(client.scanApi, 'cancelScan').mockResolvedValue({
      message: 'Scan cancellation recorded',
      data: { ...jobs[0], status: 'CANCELLED', cancellationRequested: true },
    });

    renderApp('/analyst/workspace');

    for (const status of ['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED']) {
      expect((await screen.findAllByText(status)).length).toBeGreaterThan(0);
    }
    expect(screen.getByText('SCANNER_UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /cancel scan/i })).toHaveLength(2);
    await userEvent.click(screen.getAllByRole('button', { name: /cancel scan/i })[0]);
    await waitFor(() => expect(cancelSpy).toHaveBeenCalledWith(1));
  });

  it('renders actual findings only after backend scan completion', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    vi.spyOn(client.scanApi, 'getScan').mockResolvedValue({
      data: {
        id: 91,
        targetId: 71,
        targetName: 'Approved portal',
        scanType: 'PASSIVE_HEADERS',
        status: 'COMPLETED',
        progress: 100,
        createdAt: '2026-10-20T10:00:00Z',
        startedAt: '2026-10-20T10:01:00Z',
        completedAt: '2026-10-20T10:02:00Z',
      },
    });
    const findingsSpy = vi.spyOn(client.scanApi, 'listFindings').mockResolvedValue({
      data: [{
        id: 5,
        checkType: 'CONTENT_SECURITY_POLICY',
        severity: 'MEDIUM',
        affectedComponent: 'https://portal.example.test',
        evidence: 'Content-Security-Policy header was absent',
        rationale: 'The response did not include a content security policy.',
        remediation: 'Configure a restrictive Content-Security-Policy header.',
        detectionSource: 'PASSIVE_HEADERS',
        verificationStatus: 'POTENTIAL',
        detectedAt: '2026-10-20T10:02:00Z',
      }],
    });
    const crawlPagesSpy = vi.spyOn(client.scanApi, 'listCrawlPages').mockResolvedValue({
      data: [{
        id: 12,
        url: 'https://portal.example.test/account',
        depth: 1,
        statusCode: 200,
        responseBytes: 2048,
        discoveredLinks: 3,
        discoveredAt: '2026-10-20T10:01:30Z',
      }],
    });

    renderApp('/analyst/scans/91');

    expect(await screen.findByText('Content-Security-Policy header was absent')).toBeInTheDocument();
    expect(await screen.findByText('https://portal.example.test/account')).toBeInTheDocument();
    expect(crawlPagesSpy).toHaveBeenCalledWith('91');
    expect(screen.getAllByText('CONTENT_SECURITY_POLICY').length).toBeGreaterThan(0);
    expect(screen.getByText('POTENTIAL')).toBeInTheDocument();
    expect(findingsSpy).toHaveBeenCalledWith('91');
    expect(screen.queryByText(/CVE-/i)).not.toBeInTheDocument();
  });

  it('does not present stale findings after a failed findings reload', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    vi.spyOn(client.scanApi, 'getScan').mockResolvedValue({
      data: {
        id: 92,
        targetId: 71,
        targetName: 'Approved portal',
        scanType: 'PASSIVE_HEADERS',
        status: 'COMPLETED',
        progress: 100,
      },
    });
    vi.spyOn(client.scanApi, 'listCrawlPages').mockResolvedValue({ data: [] });
    vi.spyOn(client.scanApi, 'listFindings').mockRejectedValue(
      Object.assign(new Error('You are not authorized to perform this action.'), { status: 403 }),
    );

    renderApp('/analyst/scans/92');

    expect(await screen.findByRole('alert')).toHaveTextContent(/not authorized/i);
    expect(screen.queryByText(/evidence/i)).not.toBeInTheDocument();
    expect(screen.getByText(/retry findings/i)).toBeInTheDocument();
  });

  it('renders failed scans with backend failure details and no findings', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    const findingsSpy = vi.spyOn(client.scanApi, 'listFindings');
    const crawlPagesSpy = vi.spyOn(client.scanApi, 'listCrawlPages').mockResolvedValue({ data: [] });
    vi.spyOn(client.scanApi, 'getScan').mockResolvedValue({
      data: {
        id: 93,
        targetId: 3,
        targetName: 'Timed-out target',
        scanType: 'PASSIVE_HEADERS',
        status: 'FAILED',
        progress: 10,
        statusMessage: 'Target request timed out',
        failureReason: 'TIME_BUDGET_EXCEEDED',
      },
    });

    renderApp('/analyst/scans/93');

    expect(await screen.findByText('FAILED')).toBeInTheDocument();
    expect(screen.getByText('10%')).toBeInTheDocument();
    expect(screen.getByText('TIME_BUDGET_EXCEEDED')).toBeInTheDocument();
    expect(screen.getByText('Target request timed out')).toBeInTheDocument();
    expect(screen.getByText(/findings are available after the backend confirms scan completion/i)).toBeInTheDocument();
    expect(findingsSpy).not.toHaveBeenCalled();
    expect(crawlPagesSpy).toHaveBeenCalledWith('93');
  });

  it('surfaces a backend not-found response for a scan outside the authorized organization', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    vi.spyOn(client.scanApi, 'getScan').mockRejectedValue(
      Object.assign(new Error('The requested resource was not found.'), { status: 404 }),
    );

    renderApp('/analyst/scans/999');

    expect(await screen.findByRole('alert')).toHaveTextContent(/resource was not found/i);
    expect(screen.queryByText(/evidence/i)).not.toBeInTheDocument();
  });

  it('renders report data and triggers exports using authenticated scanApi.exportReport', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    vi.spyOn(client.scanApi, 'getScan').mockResolvedValue({
      data: {
        id: 94,
        targetId: 10,
        targetName: 'Audit Target',
        scanType: 'PASSIVE_HEADERS',
        status: 'COMPLETED',
        progress: 100,
      },
    });
    vi.spyOn(client.scanApi, 'listFindings').mockResolvedValue({ data: [] });
    vi.spyOn(client.scanApi, 'listCrawlPages').mockResolvedValue({ data: [] });
    const getReportSpy = vi.spyOn(client.scanApi, 'getReport').mockResolvedValue({
      data: {
        scanId: 94,
        targetId: 10,
        targetName: 'Audit Target',
        targetUrl: 'https://audit.example.test',
        scanType: 'PASSIVE_HEADERS',
        status: 'COMPLETED',
        organizationId: 5,
        organizationName: 'Acme Sec',
        severitySummary: { high: 1, medium: 2, low: 3, total: 6 },
        totalFindings: 6,
        totalCrawlPages: 4,
        findings: [],
      },
    });

    const exportSpy = vi.spyOn(client.scanApi, 'exportReport').mockResolvedValue({
      blob: new Blob(['fake-pdf-content'], { type: 'application/pdf' }),
      filename: 'scan-report-94.pdf',
    });

    const createObjectURL = vi.fn().mockReturnValue('blob:http://localhost/fake-url');
    const revokeObjectURL = vi.fn();
    window.URL.createObjectURL = createObjectURL;
    window.URL.revokeObjectURL = revokeObjectURL;

    renderApp('/analyst/scans/94');

    expect(await screen.findByText(/Summary for Audit Target/i)).toBeInTheDocument();
    expect(screen.getByText('Organization: Acme Sec')).toBeInTheDocument();
    expect(screen.getByText('https://audit.example.test')).toBeInTheDocument();
    expect(screen.getByText('6')).toBeInTheDocument(); // total findings
    expect(screen.getByText('4')).toBeInTheDocument(); // crawl pages
    expect(getReportSpy).toHaveBeenCalledWith('94');

    // Click Export PDF
    await userEvent.click(screen.getByRole('button', { name: /export pdf/i }));
    await waitFor(() => {
      expect(exportSpy).toHaveBeenCalledWith('94', 'pdf');
      expect(createObjectURL).toHaveBeenCalled();
    });
  });

  it('handles report export errors honestly without crashing', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    vi.spyOn(client.scanApi, 'getScan').mockResolvedValue({
      data: {
        id: 95,
        targetId: 10,
        targetName: 'Target 95',
        scanType: 'PASSIVE_HEADERS',
        status: 'COMPLETED',
        progress: 100,
      },
    });
    vi.spyOn(client.scanApi, 'listFindings').mockResolvedValue({ data: [] });
    vi.spyOn(client.scanApi, 'listCrawlPages').mockResolvedValue({ data: [] });
    vi.spyOn(client.scanApi, 'getReport').mockResolvedValue({
      data: {
        scanId: 95,
        targetId: 10,
        targetName: 'Target 95',
        status: 'COMPLETED',
        severitySummary: { high: 0, medium: 0, low: 0, total: 0 },
        totalFindings: 0,
        totalCrawlPages: 0,
      },
    });
    vi.spyOn(client.scanApi, 'exportReport').mockRejectedValue(
      new Error('Failed to serialize report to JSON'),
    );

    renderApp('/analyst/scans/95');

    expect(await screen.findByText(/Summary for Target 95/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /export json/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/failed to serialize report to json/i);
  });

  it('renders CVE match details from evidence with NVD CVSS breakdown without claiming false exploitation', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    vi.spyOn(client.scanApi, 'getScan').mockResolvedValue({
      data: {
        id: 96,
        targetId: 11,
        targetName: 'CVE Target',
        scanType: 'PASSIVE_HEADERS',
        status: 'COMPLETED',
        progress: 100,
      },
    });
    vi.spyOn(client.scanApi, 'listCrawlPages').mockResolvedValue({ data: [] });
    vi.spyOn(client.scanApi, 'listFindings').mockResolvedValue({
      data: [{
        id: 401,
        checkType: 'KNOWN_VULNERABILITY_CVE',
        severity: 'HIGH',
        affectedComponent: 'Server: Apache/2.4.49 [CVE-2021-41773]',
        evidence: "Software 'Apache' version '2.4.49' disclosed in 'Server' matches CVE-2021-41773 (CVSS score: 7.5, severity: HIGH, vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N): Path traversal and file disclosure defect.",
        rationale: 'Known vulnerability in detected software version.',
        remediation: 'Upgrade Apache to a supported, patched version.',
        detectionSource: 'NVD_CVE_LOOKUP',
        verificationStatus: 'POTENTIAL',
        detectedAt: '2026-10-21T10:00:00Z',
      }],
    });

    renderApp('/analyst/scans/96');

    expect(await screen.findByText('Known vulnerability / NVD lookup')).toBeInTheDocument();
    expect(screen.getByText('CVE-2021-41773')).toBeInTheDocument();
    expect(screen.getByText(/Potential match from software version/i)).toBeInTheDocument();
    expect(screen.getByText('NVD CVSS details')).toBeInTheDocument();
    expect(screen.getByText(/Score: 7\.5/)).toBeInTheDocument();
    expect(screen.getByText(/NVD-sourced metric; local scanner severity is HIGH/i)).toBeInTheDocument();
    expect(screen.getByText('POTENTIAL')).toBeInTheDocument();
  });

  it('renders scan engine and formats native and ZAP detection sources accurately', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-analyst-token',
      user: {
        roles: ['SECURITY_ANALYST'],
        accountStatus: 'ACTIVE',
        membershipApprovalStatus: 'APPROVED',
        organizationStatus: 'APPROVED',
      },
    }));
    vi.spyOn(client.scanApi, 'getScan').mockResolvedValue({
      data: {
        id: 97,
        targetId: 12,
        targetName: 'Hybrid Target',
        scanType: 'PASSIVE_HEADERS',
        status: 'COMPLETED',
        progress: 100,
        executionSummary: {
          nativeEngineStatus: 'COMPLETED',
          zapEngineStatus: 'NOT_REQUESTED',
          discoveredPageCount: 2,
          visitedPageCount: 2,
          testedPassivePageCount: 2,
          checksInScope: ['Cookie attribute observations'],
          checksOutOfScope: ['OWASP ZAP spider or passive analysis'],
        },
      },
    });
    vi.spyOn(client.scanApi, 'listCrawlPages').mockResolvedValue({ data: [] });
    vi.spyOn(client.scanApi, 'listFindings').mockResolvedValue({
      data: [
        {
          id: 501,
          checkType: 'X_FRAME_OPTIONS',
          severity: 'MEDIUM',
          affectedComponent: 'X-Frame-Options',
          evidence: 'Header missing',
          rationale: 'Clickjacking risk',
          remediation: 'Add header',
          detectionSource: 'PASSIVE_HEADERS',
          verificationStatus: 'VERIFIED',
          detectedAt: '2026-10-21T10:00:00Z',
        },
        {
          id: 502,
          checkType: 'SQL_INJECTION_ACTIVE',
          severity: 'HIGH',
          affectedComponent: 'https://hybrid.example.test/search?q=test',
          evidence: 'SQL syntax error reflected',
          rationale: 'Active injection possible',
          remediation: 'Use parameterized queries',
          detectionSource: 'ZAP_ACTIVE',
          verificationStatus: 'VERIFIED',
          detectedAt: '2026-10-21T10:01:00Z',
        },
      ],
    });

    renderApp('/analyst/scans/97');

    expect((await screen.findAllByText('Native Header Engine')).length).toBeGreaterThan(0);
    expect(screen.getByText('NOT_REQUESTED')).toBeInTheDocument();
    expect(screen.getAllByText(/Discovered same-origin pages/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/OWASP ZAP spider or passive analysis/i)).toBeInTheDocument();
    expect(screen.getAllByText('OWASP ZAP').length).toBeGreaterThan(0);
    expect(screen.getAllByText('X_FRAME_OPTIONS').length).toBeGreaterThan(0);
    expect(screen.getAllByText('SQL_INJECTION_ACTIVE').length).toBeGreaterThan(0);
  });

  it('renders Super Admin organization approvals page with real workflow and confirmation', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-super-token',
      user: { username: 'super-admin', roles: ['SUPER_ADMIN'] },
    }));

    let pending = [{ id: 101, name: 'OWASP', contactEmail: 'security@owasp.org', status: 'PENDING' }];
    let approved = [];
    vi.spyOn(client.organizationApi, 'listPendingRegistrations').mockImplementation(async () => ({
      data: pending,
    }));
    const registrySpy = vi.spyOn(client.organizationApi, 'getRegistry').mockImplementation(async () => ({
      data: { ownOrganization: null, approvedOrganizations: approved },
    }));
    vi.spyOn(client.organizationApi, 'listOrganizationAdmins').mockResolvedValue({
      data: { content: [], totalElements: 0, totalPages: 0, number: 0 },
    });
    const decideSpy = vi.spyOn(client.organizationApi, 'decideRegistration').mockImplementation(async () => {
      pending = [];
      approved = [{
        id: 101,
        name: 'OWASP',
        status: 'APPROVED',
        ownOrganization: false,
        adminDisplayName: 'Jordan Admin',
      }];
      return {
        message: 'Organization approved successfully.',
        data: { status: 'APPROVED' },
      };
    });

    renderApp('/super-admin/organizations');

    await waitFor(() => {
      expect(screen.getByText('OWASP')).toBeInTheDocument();
      expect(screen.queryByText('security@owasp.org')).not.toBeInTheDocument();
      expect(screen.getByText('Primary contact').nextElementSibling).toHaveTextContent('Name unavailable');
      expect(screen.getByText('PENDING')).toHaveAttribute('data-status', 'PENDING');
    });

    const approveButton = screen.getByRole('button', { name: /^approve$/i });
    await userEvent.click(approveButton);

    // Confirmation dialog opens
    expect(screen.getByText(/are you sure you want to approve the registration for owasp/i)).toBeInTheDocument();

    const confirmButton = screen.getAllByRole('button', { name: /^approve$/i })[1];
    await userEvent.click(confirmButton);

    await waitFor(() => {
      expect(decideSpy).toHaveBeenCalledWith(101, 'APPROVE');
      expect(screen.getByText(/status: approved/i)).toBeInTheDocument();
      expect(screen.getByText('Organization Admin').nextElementSibling).toHaveTextContent('Jordan Admin');
      expect(registrySpy).toHaveBeenCalledTimes(2);
    });
  });

  it('limits the Super Admin approval view to review and decision actions', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-super-token',
      user: { username: 'super-admin', roles: ['SUPER_ADMIN'] },
    }));

    vi.spyOn(client.organizationApi, 'listPendingRegistrations').mockResolvedValue({
      data: [{
        id: 102,
        name: 'Omega Tech',
        primaryContactName: 'Taylor Security',
        contactEmail: 'admin@omega.com',
        status: 'PENDING',
      }],
    });
    vi.spyOn(client.organizationApi, 'getRegistry').mockResolvedValue({
      data: {
        ownOrganization: null,
        approvedOrganizations: [{
          id: 103,
          name: 'Northstar',
          status: 'APPROVED',
          ownOrganization: false,
          registeredAt: '2026-10-01T00:00:00Z',
          approvedAt: '2026-10-02T00:00:00Z',
          adminDisplayName: 'Jordan Admin',
        }],
      },
    });
    vi.spyOn(client.organizationApi, 'listOrganizationAdmins').mockResolvedValue({
      data: { content: [], totalElements: 0, totalPages: 0, number: 0 },
    });

    renderApp('/super-admin/organizations');

    await waitFor(() => {
      expect(screen.getByText('Omega Tech')).toBeInTheDocument();
      expect(screen.getByText('Taylor Security')).toBeInTheDocument();
      expect(screen.getByText('Northstar')).toBeInTheDocument();
      expect(screen.getByText('Jordan Admin')).toBeInTheDocument();
      expect(screen.queryByText('admin@omega.com')).not.toBeInTheDocument();
    });

    expect(screen.getByRole('button', { name: /^approve$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^reject$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /deactivate organization/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^delete$/i })).not.toBeInTheDocument();
    expect(screen.queryByText('102')).not.toBeInTheDocument();
  });

  it('loads the authenticated Super Admin organization metadata without exposing deletion', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-super-token',
      user: { organizationId: 707, roles: ['SUPER_ADMIN'] },
    }));
    vi.spyOn(client.organizationApi, 'listPendingRegistrations').mockResolvedValue({ data: [] });
    vi.spyOn(client.organizationApi, 'getRegistry').mockResolvedValue({
      data: { ownOrganization: null, approvedOrganizations: [] },
    });
    vi.spyOn(client.organizationApi, 'listOrganizationAdmins').mockResolvedValue({
      data: { content: [], totalElements: 0, totalPages: 0, number: 0 },
    });
    const ownOrganizationSpy = vi.spyOn(client.organizationApi, 'getOrganization').mockResolvedValue({
      data: {
        id: 707,
        name: 'Platform Organization',
        status: 'SUSPENDED',
        registrationAdminFirstName: 'Morgan',
        registrationAdminLastName: 'Admin',
      },
    });

    renderApp('/super-admin/organizations');

    expect(await screen.findByText('Platform Organization')).toBeInTheDocument();
    expect(screen.getByText('Your organization')).toBeInTheDocument();
    expect(screen.getByText('Organization Admin').nextElementSibling).toHaveTextContent('Morgan Admin');
    expect(screen.queryByRole('button', { name: /deactivate organization/i })).not.toBeInTheDocument();
    expect(ownOrganizationSpy).toHaveBeenCalledWith(707);
  });

  it('manages Organization Admin accounts using backend status and confirmed lifecycle actions', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-super-token',
      user: { roles: ['SUPER_ADMIN'] },
    }));
    vi.spyOn(client.organizationApi, 'listPendingRegistrations').mockResolvedValue({ data: [] });
    vi.spyOn(client.organizationApi, 'getRegistry').mockResolvedValue({
      data: { ownOrganization: null, approvedOrganizations: [] },
    });
    const adminRecord = {
      userId: 32,
      displayName: 'Riley Admin',
      roles: ['ADMIN'],
      status: 'ACTIVE',
      createdAt: '2026-09-01T00:00:00Z',
    };
    vi.spyOn(client.organizationApi, 'listOrganizationAdmins').mockImplementation(async () => ({
      data: { content: [adminRecord], totalElements: 1, totalPages: 1, number: 0 },
    }));
    const updateSpy = vi.spyOn(client.organizationApi, 'updateOrganizationAdmin').mockImplementation(async () => {
      adminRecord.status = 'SUSPENDED';
      return {
        message: 'Organization administrator suspended',
        data: { ...adminRecord },
      };
    });

    renderApp('/super-admin/organizations');
    expect(await screen.findByText('Riley Admin')).toBeInTheDocument();
    expect(screen.queryByText(/@/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /^suspend$/i }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /suspend/i }));

    await waitFor(() => {
      expect(updateSpy).toHaveBeenCalledWith(32, 'suspend');
      expect(screen.queryByLabelText(/reason/i)).not.toBeInTheDocument();
      expect(screen.getByText(/status: suspended/i)).toBeInTheDocument();
      expect(screen.getByText('SUSPENDED')).toBeInTheDocument();
    });
  });

  it('creates, approves, deactivates, and refreshes organization targets from API results', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-admin-token',
      user: { id: 7, roles: ['ADMIN'] },
    }));
    let targets = [];
    const listSpy = vi.spyOn(client.targetApi, 'listTargets').mockImplementation(async () => ({ data: targets }));
    const createSpy = vi.spyOn(client.targetApi, 'createTarget').mockImplementation(async (payload) => {
      targets = [{ id: 51, ...payload, organizationId: 12, status: 'PENDING' }];
      return { message: 'Target created', data: targets[0] };
    });
    const decisionSpy = vi.spyOn(client.targetApi, 'decideTarget').mockImplementation(async (id, decision) => {
      targets = targets.map((target) => target.id === id
        ? { ...target, status: decision === 'APPROVE' ? 'APPROVED' : 'REJECTED' }
        : target);
      return { message: 'Target decision recorded', data: targets[0] };
    });
    const deleteSpy = vi.spyOn(client.targetApi, 'deleteTarget').mockImplementation(async () => {
      const deleted = { ...targets[0], status: 'DELETED' };
      targets = [];
      return { message: 'Target deactivated', data: deleted };
    });

    renderApp('/admin/targets');
    await userEvent.click(await screen.findByRole('button', { name: /\+ add target/i }));
    await userEvent.type(screen.getByLabelText(/target name/i), 'OWASP staging');
    await userEvent.type(screen.getByLabelText(/target url/i), 'https://staging.example.test');
    await userEvent.click(screen.getByRole('button', { name: /create target/i }));

    expect(await screen.findByText('OWASP staging')).toBeInTheDocument();
    expect(createSpy).toHaveBeenCalledWith({
      name: 'OWASP staging',
      url: 'https://staging.example.test',
      type: 'WEB_APPLICATION',
    });
    expect(listSpy).toHaveBeenCalledTimes(2);

    await userEvent.click(screen.getByRole('button', { name: /approve/i }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /approve/i }));
    await waitFor(() => {
      expect(decisionSpy).toHaveBeenCalledWith(51, 'APPROVE');
      expect(screen.getByText('APPROVED')).toBeInTheDocument();
    });

    await userEvent.click(screen.getByRole('button', { name: /deactivate/i }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /deactivate/i }));
    await waitFor(() => {
      expect(deleteSpy).toHaveBeenCalledWith(51);
      expect(listSpy).toHaveBeenCalledTimes(4);
      expect(screen.getByText(/target deactivated/i)).toBeInTheDocument();
    });
  });

  it('rejects a pending target and shows the refreshed API status', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-admin-token',
      user: { id: 7, roles: ['ADMIN'] },
    }));
    let target = {
      id: 81,
      name: 'Pending portal',
      url: 'https://pending.example.test',
      type: 'WEB_APPLICATION',
      status: 'PENDING',
    };
    vi.spyOn(client.targetApi, 'listTargets').mockImplementation(async () => ({ data: [target] }));
    const decideSpy = vi.spyOn(client.targetApi, 'decideTarget').mockImplementation(async (_id, decision) => {
      target = { ...target, status: decision === 'REJECT' ? 'REJECTED' : 'APPROVED' };
      return { message: 'Target decision recorded', data: target };
    });

    renderApp('/admin/targets');
    await screen.findByRole('heading', { name: 'Pending portal' });
    await userEvent.click(screen.getByRole('button', { name: /reject/i }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /reject/i }));

    await waitFor(() => {
      expect(decideSpy).toHaveBeenCalledWith(81, 'REJECT');
      expect(screen.getByText('REJECTED')).toBeInTheDocument();
    });
  });

  it('shows target API authorization errors and a real empty state', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-admin-token',
      user: { id: 7, roles: ['ADMIN'] },
    }));
    vi.spyOn(client.targetApi, 'listTargets')
      .mockRejectedValueOnce(Object.assign(new Error('You are not authorized to perform this action.'), { status: 403 }))
      .mockResolvedValueOnce({ data: [] });

    const { unmount } = renderApp('/admin/targets');
    expect(await screen.findByRole('alert')).toHaveTextContent(/not authorized/i);
    unmount();

    renderApp('/admin/targets');
    expect(await screen.findByText(/no targets are currently available/i)).toBeInTheDocument();
  });

  it('uses authenticated organization-scoped APIs for analyst approval and user management', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'valid-admin-token',
      user: { id: 7, username: 'admin', roles: ['ADMIN'] },
    }));
    const analyst = {
      userId: 44,
      displayName: 'Casey Analyst',
      roles: ['SECURITY_ANALYST'],
      status: 'PENDING_APPROVAL',
      createdAt: '2026-10-01T00:00:00Z',
    };
    vi.spyOn(client.organizationApi, 'getDashboard').mockResolvedValue({
      data: {
        totalUsers: 3,
        approvedUsers: 2,
        pendingApprovalRequests: 1,
        suspendedUsers: 0,
        activeSecurityAnalysts: 1,
      },
    });
    const listUsersSpy = vi.spyOn(client.organizationApi, 'listUsers').mockImplementation(({ status }) => Promise.resolve({
      data: {
        content: status === 'PENDING_APPROVAL'
          ? analyst.status === 'PENDING_APPROVAL' ? [analyst] : []
          : [analyst],
        totalElements: 1,
        totalPages: 1,
        number: 0,
      },
    }));
    vi.spyOn(client.organizationApi, 'getUser').mockResolvedValue({ data: analyst });
    const decideSpy = vi.spyOn(client.organizationApi, 'decideApproval').mockImplementation(async (userId, decision) => {
      analyst.status = decision === 'APPROVE' ? 'ACTIVE' : 'DISABLED';
      return { message: 'Membership approved', data: { status: analyst.status } };
    });
    const userActionSpy = vi.spyOn(client.organizationApi, 'updateUserStatus').mockImplementation(async (userId, action) => {
      analyst.status = {
        suspend: 'SUSPENDED',
        restore: 'ACTIVE',
        deactivate: 'DISABLED',
      }[action];
      return { message: `User ${action}d`, data: { status: analyst.status } };
    });

    renderApp('/admin/analysts');
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Casey Analyst' })).toBeInTheDocument();
      expect(screen.getByRole('heading', { name: /organization dashboard/i })).toBeInTheDocument();
      expect(screen.getByRole('heading', { name: /pending security analyst requests/i })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: /display name/i })).toBeInTheDocument();
      expect(screen.getByText('3', { selector: 'p' })).toBeInTheDocument();
    });
    expect(listUsersSpy).toHaveBeenCalledWith(expect.objectContaining({
      role: 'SECURITY_ANALYST',
      status: 'PENDING_APPROVAL',
    }));
    expect(listUsersSpy.mock.calls[0][0]).not.toHaveProperty('organizationId');

    await userEvent.click(screen.getAllByRole('button', { name: /view details/i })[0]);
    expect(await screen.findByRole('dialog')).toHaveTextContent('SECURITY_ANALYST');
    expect(screen.getByRole('dialog')).toHaveTextContent('PENDING APPROVAL');
    await userEvent.click(screen.getByRole('button', { name: /close/i }));

    await userEvent.click(screen.getByRole('button', { name: /^approve$/i }));
    const dialog = screen.getByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: /approve/i }));

    await waitFor(() => {
      expect(decideSpy).toHaveBeenCalledWith(44, 'APPROVE');
      expect(screen.getByText(/status: active/i)).toBeInTheDocument();
    });

    await userEvent.click(await screen.findByRole('button', { name: /suspend/i }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /suspend/i }));
    await waitFor(() => {
      expect(userActionSpy).toHaveBeenCalledWith(44, 'suspend');
      expect(screen.getByText(/status: suspended/i)).toBeInTheDocument();
    });

    await userEvent.click(await screen.findByRole('button', { name: /restore/i }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /restore/i }));
    await waitFor(() => {
      expect(userActionSpy).toHaveBeenCalledWith(44, 'restore');
      expect(screen.getByText(/status: active/i)).toBeInTheDocument();
    });

    await userEvent.click(await screen.findByRole('button', { name: /deactivate/i }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /deactivate/i }));
    await waitFor(() => {
      expect(userActionSpy).toHaveBeenCalledWith(44, 'deactivate');
      expect(screen.getByText(/status: disabled/i)).toBeInTheDocument();
    });
  });

  it('handles expired session events by clearing state', async () => {
    localStorage.setItem('scanner-auth-session', JSON.stringify({
      token: 'expired-token',
      user: { username: 'admin-user', roles: ['ADMIN'] },
    }));

    renderApp('/');

    await waitFor(() => {
      expect(screen.getByText(/target management/i)).toBeInTheDocument();
    });

    // Dispatch session-expired
    act(() => {
      window.dispatchEvent(new CustomEvent('auth:session-expired'));
    });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
    });
  });
});
