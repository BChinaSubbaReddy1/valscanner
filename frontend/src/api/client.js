const STORAGE_KEY = 'scanner-auth-session';

export const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';

function readSession() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function writeSession(session) {
  if (!session) {
    localStorage.removeItem(STORAGE_KEY);
    return;
  }

  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

export function readStoredSession() {
  return readSession();
}

function parseResponse(response) {
  const contentType = response.headers.get('content-type') || '';

  if (contentType.includes('application/json')) {
    return response.json().catch(() => null);
  }

  return response.text().catch(() => null);
}

export async function apiRequest(endpoint, options = {}) {
  const session = readSession();
  const headers = new Headers(options.headers || {});
  const requestInit = {
    ...options,
    credentials: options.credentials ?? 'include',
    headers,
  };

  if (!(options.body instanceof FormData) && !(options.body instanceof URLSearchParams)) {
    if (!headers.has('Content-Type') && typeof options.body !== 'undefined') {
      headers.set('Content-Type', 'application/json');
    }
  }

  if (session?.token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${session.token}`);
  }

  if (
    options.body &&
    typeof options.body !== 'string' &&
    !(options.body instanceof FormData) &&
    !(options.body instanceof URLSearchParams) &&
    !(options.body instanceof Blob)
  ) {
    requestInit.body = JSON.stringify(options.body);
  }

  let response;
  try {
    response = await fetch(`${BASE_URL}${endpoint}`, requestInit);
  } catch {
    throw new Error('Network request failed. Check your connection and try again.');
  }

  if (response.status === 401 && session?.token) {
    writeSession(null);
    window.dispatchEvent(new CustomEvent('auth:session-expired'));
  }

  const payload = await parseResponse(response);

  if (!response.ok || (payload && typeof payload === 'object' && payload.success === false)) {
    const serverMessage = payload && typeof payload === 'object'
      ? payload.message || payload.error || payload.detail
      : null;
    const message = serverMessage || ({
      400: 'The request was invalid. Check the submitted details.',
      401: session?.token
        ? 'Your session has expired. Sign in again.'
        : 'Authentication failed. Check your credentials or sign in again.',
      403: 'You are not authorized to perform this action.',
      404: 'The requested resource was not found.',
      409: 'This request conflicts with existing data.',
    }[response.status]) || (response.status >= 500
      ? 'The server could not complete the request. Try again later.'
      : 'The request could not be completed.');

    const error = new Error(message);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }

  return payload;
}

export const authApi = {
  async login(credentials) {
    return apiRequest('/api/auth/login', {
      method: 'POST',
      body: { email: credentials.email, password: credentials.password },
    });
  },

  async register(payload) {
    return apiRequest('/api/auth/register', {
      method: 'POST',
      body: payload,
    });
  },

  async forgotPassword(payload) {
    return apiRequest('/api/auth/forgot-password', {
      method: 'POST',
      body: payload,
    });
  },

  async resetPassword(payload) {
    return apiRequest('/api/auth/reset-password', {
      method: 'POST',
      body: payload,
    });
  },

  async currentUser() {
    return apiRequest('/api/users/me', {
      method: 'GET',
    });
  },

  async logout() {
    return apiRequest('/api/auth/logout', {
      method: 'POST',
    });
  },
};

export const organizationApi = {
  async listPendingRegistrations() {
    return apiRequest('/api/organizations/pending', {
      method: 'GET',
    });
  },

  // Organization registration is restricted to Super Admins by the backend.
  async register(payload) {
    return apiRequest('/api/organizations/register', {
      method: 'POST',
      body: payload,
    });
  },

  async decideRegistration(organizationId, decision) {
    if (decision !== 'APPROVE' && decision !== 'REJECT') {
      throw new Error('Organization decision must be APPROVE or REJECT.');
    }
    const action = decision === 'APPROVE' ? 'approve' : 'reject';
    return apiRequest(`/api/organizations/${organizationId}/${action}`, {
      method: 'POST',
      body: {},
    });
  },

  async getRegistry() {
    return apiRequest('/api/organizations/registry', {
      method: 'GET',
    });
  },

  async getOrganization(organizationId) {
    return apiRequest(`/api/organizations/${organizationId}`, {
      method: 'GET',
    });
  },

  async deleteOrganization(organizationId) {
    return apiRequest(`/api/organizations/${organizationId}`, {
      method: 'DELETE',
      body: {},
    });
  },

  async getDashboard() {
    return apiRequest('/api/organizations/me/dashboard', {
      method: 'GET',
    });
  },

  async getPlatformDashboard() {
    return apiRequest('/api/organizations/platform-dashboard', {
      method: 'GET',
    });
  },

  async listUsers({ role, status, search, page = 0, size = 20 } = {}) {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    if (role) params.set('role', role);
    if (status) params.set('status', status);
    if (search?.trim()) params.set('search', search.trim());
    return apiRequest(`/api/organizations/me/users?${params.toString()}`, {
      method: 'GET',
    });
  },

  async getUser(userId) {
    return apiRequest(`/api/organizations/me/users/${userId}`, {
      method: 'GET',
    });
  },

  async listApprovalRequests({ page = 0, size = 20 } = {}) {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    return apiRequest(`/api/organizations/me/approval-requests?${params.toString()}`, {
      method: 'GET',
    });
  },

  async decideApproval(userId, decision) {
    if (decision !== 'APPROVE' && decision !== 'REJECT') {
      throw new Error('Membership decision must be APPROVE or REJECT.');
    }
    const action = decision === 'APPROVE' ? 'approve' : 'reject';
    return apiRequest(`/api/organizations/me/approval-requests/${userId}/${action}`, {
      method: 'POST',
      body: {},
    });
  },

  async updateUserStatus(userId, action) {
    if (!['suspend', 'restore', 'deactivate'].includes(action)) {
      throw new Error('Unsupported organization user action.');
    }
    return apiRequest(`/api/organizations/me/users/${userId}/${action}`, {
      method: 'POST',
      body: {},
    });
  },

  async listOrganizationAdmins({ status, page = 0, size = 20 } = {}) {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    if (status) params.set('status', status);
    return apiRequest(`/api/organizations/admin-accounts?${params.toString()}`, {
      method: 'GET',
    });
  },

  async updateOrganizationAdmin(userId, action) {
    if (!['suspend', 'restore', 'deactivate'].includes(action)) {
      throw new Error('Unsupported Organization Admin account action.');
    }
    return apiRequest(`/api/organizations/admin-accounts/${userId}/${action}`, {
      method: 'POST',
      body: {},
    });
  },

  async listPendingMembershipRequests(organizationId) {
    return apiRequest(`/api/organizations/${organizationId}/membership-requests`, {
      method: 'GET',
    });
  },

  async listMembers(organizationId) {
    return apiRequest(`/api/organizations/${organizationId}/members`, {
      method: 'GET',
    });
  },

  async decideMembership(organizationId, userId, decision) {
    if (decision !== 'APPROVE' && decision !== 'REJECT') {
      throw new Error('Membership decision must be APPROVE or REJECT.');
    }
    const action = decision === 'APPROVE' ? 'approve' : 'reject';
    return apiRequest(`/api/organizations/${organizationId}/membership-requests/${userId}/${action}`, {
      method: 'POST',
    });
  },
};

export const targetApi = {
  async listTargets() {
    return apiRequest('/api/targets', {
      method: 'GET',
    });
  },

  async createTarget(payload) {
    return apiRequest('/api/targets', {
      method: 'POST',
      body: payload,
    });
  },

  async decideTarget(targetId, decision) {
    return apiRequest(`/api/targets/${targetId}/decision`, {
      method: 'POST',
      body: { decision },
    });
  },

  async deleteTarget(targetId) {
    return apiRequest(`/api/targets/${targetId}`, {
      method: 'DELETE',
    });
  },
};

export const scanApi = {
  async createScan(targetId, scanType = 'PASSIVE_HEADERS') {
    if (scanType !== 'PASSIVE_HEADERS') {
      throw new Error('Only PASSIVE_HEADERS scans are supported.');
    }
    return apiRequest('/api/scans', {
      method: 'POST',
      body: { targetId, scanType: 'PASSIVE_HEADERS' },
    });
  },

  async listScans({ page = 0, size = 20 } = {}) {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    return apiRequest(`/api/scans?${params.toString()}`, {
      method: 'GET',
    });
  },

  async getAnalystDashboard() {
    return apiRequest('/api/scans/me/dashboard', {
      method: 'GET',
    });
  },

  async listPendingApprovals({ page = 0, size = 20 } = {}) {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    return apiRequest(`/api/scans/pending-approval?${params.toString()}`, {
      method: 'GET',
    });
  },

  async approveScan(scanId) {
    return apiRequest(`/api/scans/${scanId}/approve`, {
      method: 'POST',
    });
  },

  async rejectScan(scanId, reason) {
    if (!reason?.trim()) {
      throw new Error('A rejection reason is required.');
    }
    return apiRequest(`/api/scans/${scanId}/reject`, {
      method: 'POST',
      body: { reason: reason.trim() },
    });
  },

  async getScan(scanId) {
    return apiRequest(`/api/scans/${scanId}`, {
      method: 'GET',
    });
  },

  async cancelScan(scanId) {
    return apiRequest(`/api/scans/${scanId}/cancel`, {
      method: 'POST',
    });
  },

  async listFindings(scanId) {
    return apiRequest(`/api/scans/${scanId}/findings`, {
      method: 'GET',
    });
  },

  async listCrawlPages(scanId) {
    return apiRequest(`/api/scans/${scanId}/crawl-pages`, {
      method: 'GET',
    });
  },

  async getReport(scanId) {
    return apiRequest(`/api/scans/${scanId}/report`, {
      method: 'GET',
    });
  },

  // Returns { blob, filename } — the export endpoint sends raw bytes, not a JSON envelope.
  async exportReport(scanId, format) {
    const normalizedFormat = String(format || 'json').trim().toLowerCase();
    const session = readSession();
    const headers = new Headers();
    if (session?.token) {
      headers.set('Authorization', `Bearer ${session.token}`);
    }
    let response;
    try {
      response = await fetch(
        `${BASE_URL}/api/scans/${scanId}/report/export?format=${encodeURIComponent(normalizedFormat)}`,
        { credentials: 'include', headers },
      );
    } catch {
      throw new Error('Network request failed. Check your connection and try again.');
    }
    if (response.status === 401 && session?.token) {
      writeSession(null);
      window.dispatchEvent(new CustomEvent('auth:session-expired'));
    }
    if (!response.ok) {
      // Try to parse error body if JSON
      let serverMessage = null;
      try {
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          const payload = await response.json();
          serverMessage = payload?.message || payload?.error || payload?.detail || null;
        }
      } catch {
        // ignore parse errors
      }
      const message = serverMessage || ({
        401: session?.token ? 'Your session has expired. Sign in again.' : 'Authentication failed.',
        403: 'You are not authorized to perform this action.',
        404: 'The requested resource was not found.',
      }[response.status]) || (response.status >= 500
        ? 'The server could not complete the request. Try again later.'
        : 'The request could not be completed.');
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    // Extract filename from Content-Disposition if present
    const disposition = response.headers.get('content-disposition') || '';
    const filenameMatch = disposition.match(/filename="?([^";\r\n]+)"?/i);
    const filename = filenameMatch
      ? filenameMatch[1]
      : `scan-report-${scanId}.${normalizedFormat}`;
    const blob = await response.blob();
    return { blob, filename };
  },
};
