import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../../auth/useAuth';
import { organizationApi } from '../../api/client';
import ConfirmationDialog from '../../components/ConfirmationDialog';
import LoadingSpinner from '../../components/LoadingSpinner';

const PAGE_SIZE = 20;
const STATUSES = ['ACTIVE', 'PENDING_APPROVAL', 'SUSPENDED', 'DISABLED', 'LOCKED'];

function dataOf(response) {
  return response?.data ?? response;
}

function pageOf(response) {
  const page = dataOf(response) || {};
  return {
    content: Array.isArray(page.content) ? page.content : [],
    totalElements: Number(page.totalElements) || 0,
    totalPages: Number(page.totalPages) || 0,
    number: Number(page.number) || 0,
  };
}

function rolesOf(user) {
  return Array.isArray(user?.roles) ? user.roles : [];
}

function statusLabel(status) {
  return String(status || 'Unavailable').replace(/_/g, ' ');
}

function displayDate(value) {
  if (!value) return 'Date unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Date unavailable' : date.toLocaleDateString();
}

export default function AnalystApprovalPage() {
  const { user } = useAuth();
  const [dashboard, setDashboard] = useState(null);
  const [users, setUsers] = useState({ content: [], totalElements: 0, totalPages: 0, number: 0 });
  const [requests, setRequests] = useState({ content: [], totalElements: 0, totalPages: 0, number: 0 });
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [approvalPage, setApprovalPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [activeAction, setActiveAction] = useState(null);
  const [details, setDetails] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [dashboardResult, usersResult, requestsResult] = await Promise.all([
        organizationApi.getDashboard(),
        organizationApi.listUsers({
          role: 'SECURITY_ANALYST',
          status: status || undefined,
          search,
          page,
          size: PAGE_SIZE,
        }),
        organizationApi.listUsers({
          role: 'SECURITY_ANALYST',
          status: 'PENDING_APPROVAL',
          page: approvalPage,
          size: PAGE_SIZE,
        }),
      ]);
      setDashboard(dataOf(dashboardResult));
      setUsers(pageOf(usersResult));
      setRequests(pageOf(requestsResult));
    } catch (requestError) {
      setError(requestError.message || 'Unable to load organization user information.');
    } finally {
      setLoading(false);
    }
  }, [approvalPage, page, search, status]);

  useEffect(() => {
    void Promise.resolve().then(loadData);
  }, [loadData]);

  const openAction = (entry, action, decision) => {
    setActiveAction({ entry, action, decision });
  };

  const handleAction = async () => {
    if (!activeAction) return;

    setLoading(true);
    setError('');
    setMessage('');
    try {
      const { entry, action, decision } = activeAction;
      const result = decision
        ? await organizationApi.decideApproval(entry.userId, decision)
        : await organizationApi.updateUserStatus(entry.userId, action);
      const response = dataOf(result);
      const outcome = response?.status;
      const actionLabels = {
        suspend: 'suspended',
        restore: 'restored',
        deactivate: 'deactivated',
      };
      const actionText = decision
        ? `Analyst membership ${decision === 'APPROVE' ? 'approved' : 'rejected'}`
        : `Analyst account ${actionLabels[action] || action}`;
      setMessage(`${result?.message || `${actionText} by the server.`}${outcome ? ` Status: ${statusLabel(outcome)}.` : ''}`);
      setActiveAction(null);
      await loadData();
    } catch (requestError) {
      setError(requestError.message || 'The organization user action could not be completed.');
      setLoading(false);
    }
  };

  const openDetails = async (entry) => {
    setError('');
    try {
      const result = await organizationApi.getUser(entry.userId);
      setDetails(dataOf(result));
    } catch (requestError) {
      setError(requestError.message || 'Unable to load this user.');
    }
  };

  const currentUserId = user?.id == null ? null : String(user.id);

  return (
    <section className="page-shell">
      <div className="page-header">
        <div>
          <p className="eyebrow">Organization membership</p>
          <h1>Analyst requests and users</h1>
        </div>
        <button type="button" className="secondary-button" onClick={loadData} disabled={loading}>
          Refresh
        </button>
      </div>

      {error ? <div className="message-card error" role="alert">{error}</div> : null}
      {message ? <div className="message-card success" role="status">{message}</div> : null}

      {loading && !dashboard ? (
        <LoadingSpinner label="Loading organization user information…" />
      ) : (
        <>
          <section aria-labelledby="organization-user-stats">
            <h2 id="organization-user-stats">Organization dashboard</h2>
            <div className="card-grid">
              <article className="data-card">
                <h3>Total users</h3>
                <p className="muted">{dashboard?.totalUsers ?? 'Unavailable'}</p>
              </article>
              <article className="data-card">
                <h3>Approved users</h3>
                <p className="muted">{dashboard?.approvedUsers ?? 'Unavailable'}</p>
              </article>
              <article className="data-card">
                <h3>Pending approvals</h3>
                <p className="muted">{dashboard?.pendingApprovalRequests ?? 'Unavailable'}</p>
              </article>
              <article className="data-card">
                <h3>Suspended users</h3>
                <p className="muted">{dashboard?.suspendedUsers ?? 'Unavailable'}</p>
              </article>
              <article className="data-card">
                <h3>Active Security Analysts</h3>
                <p className="muted">{dashboard?.activeSecurityAnalysts ?? 'Unavailable'}</p>
              </article>
            </div>
          </section>

          <section aria-labelledby="pending-analysts-heading">
            <div className="section-header">
              <div>
                <p className="eyebrow">Membership approval</p>
                <h2 id="pending-analysts-heading">Pending Security Analyst requests</h2>
              </div>
            </div>
            {requests.content.length === 0 ? (
              <div className="empty-state">No pending Security Analyst requests.</div>
            ) : (
              <div className="card-grid">
                {requests.content.map((request) => (
                  <article className="data-card" key={request.userId}>
                    <div className="data-card-header">
                      <div>
                        <p className="eyebrow">Security Analyst</p>
                        <h3>{request.displayName || 'Name unavailable'}</h3>
                      </div>
                      <span className="status-chip" data-status={request.status}>{statusLabel(request.status)}</span>
                    </div>
                    <p className="muted">Requested {displayDate(request.requestedAt || request.createdAt)}</p>
                    {currentUserId !== String(request.userId) ? (
                      <div className="stack-actions">
                        <button type="button" className="primary-button" disabled={loading} onClick={() => openAction(request, null, 'APPROVE')}>
                          Approve
                        </button>
                        <button type="button" className="secondary-button" disabled={loading} onClick={() => openAction(request, null, 'REJECT')}>
                          Reject
                        </button>
                      </div>
                    ) : <p className="muted">You cannot approve your own membership.</p>}
                  </article>
                ))}
              </div>
            )}
            {requests.totalPages > 1 ? (
              <div className="user-table-pagination">
                <span>{requests.totalElements} pending requests</span>
                <div className="inline-actions">
                  <button type="button" className="secondary-button" disabled={approvalPage <= 0 || loading} onClick={() => setApprovalPage((current) => current - 1)}>Previous</button>
                  <span>Page {approvalPage + 1} of {requests.totalPages}</span>
                  <button type="button" className="secondary-button" disabled={approvalPage + 1 >= requests.totalPages || loading} onClick={() => setApprovalPage((current) => current + 1)}>Next</button>
                </div>
              </div>
            ) : null}
          </section>

          <section aria-labelledby="organization-users-heading">
            <div className="section-header">
              <div>
                <p className="eyebrow">Organization membership</p>
                <h2 id="organization-users-heading">Security Analysts</h2>
              </div>
            </div>
            <div className="user-management-controls">
              <label>
                Filter by status
                <select
                  value={status}
                  onChange={(event) => {
                    setStatus(event.target.value);
                    setPage(0);
                  }}
                >
                  <option value="">All statuses</option>
                  {STATUSES.map((value) => <option key={value} value={value}>{statusLabel(value)}</option>)}
                </select>
              </label>
              <label>
                Search by name
                <input
                  type="search"
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value);
                    setPage(0);
                  }}
                  placeholder="Search Security Analysts"
                />
              </label>
            </div>

            {users.content.length === 0 ? (
              <div className="empty-state">No Security Analysts match the selected status or search.</div>
            ) : (
              <>
                <div className="user-table-scroll">
                  <div className="list-table user-management-table" role="table" aria-label="Organization Security Analysts">
                    <div className="table-row user-management-row table-row--header" role="row">
                      <span role="columnheader">Display name</span>
                      <span role="columnheader">Role</span>
                      <span role="columnheader">Account status</span>
                      <span role="columnheader">Registration date</span>
                      <span role="columnheader">Actions</span>
                    </div>
                    {users.content.map((entry) => {
                      const isSelf = currentUserId === String(entry.userId);
                      return (
                        <div className="table-row user-management-row" role="row" key={entry.userId}>
                          <span role="cell">{entry.displayName || 'Name unavailable'}</span>
                          <span role="cell">Security Analyst</span>
                          <span role="cell">
                            <span className="status-chip" data-status={entry.status}>{statusLabel(entry.status)}</span>
                          </span>
                          <span role="cell">{displayDate(entry.createdAt)}</span>
                          <span role="cell" className="user-management-actions">
                            <button type="button" className="secondary-button" onClick={() => openDetails(entry)}>View details</button>
                            {!isSelf && entry.status === 'ACTIVE' ? (
                              <>
                                <button type="button" className="secondary-button" disabled={loading} onClick={() => openAction(entry, 'suspend')}>Suspend</button>
                                <button type="button" className="danger-button" disabled={loading} onClick={() => openAction(entry, 'deactivate')}>Deactivate</button>
                              </>
                            ) : null}
                            {!isSelf && entry.status === 'SUSPENDED' ? (
                              <>
                                <button type="button" className="primary-button" disabled={loading} onClick={() => openAction(entry, 'restore')}>Restore</button>
                                <button type="button" className="danger-button" disabled={loading} onClick={() => openAction(entry, 'deactivate')}>Deactivate</button>
                              </>
                            ) : null}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div className="user-table-pagination">
                  <span>{users.totalElements} Security Analyst{users.totalElements === 1 ? '' : 's'}</span>
                  <div className="inline-actions">
                    <button type="button" className="secondary-button" disabled={page <= 0 || loading} onClick={() => setPage((current) => current - 1)}>Previous</button>
                    <span>Page {users.number + 1} of {Math.max(1, users.totalPages)}</span>
                    <button type="button" className="secondary-button" disabled={page + 1 >= users.totalPages || loading} onClick={() => setPage((current) => current + 1)}>Next</button>
                  </div>
                </div>
              </>
            )}
          </section>
        </>
      )}

      <ConfirmationDialog
        open={Boolean(activeAction)}
        title={activeAction?.decision
          ? `${activeAction.decision === 'APPROVE' ? 'Approve' : 'Reject'} analyst membership`
          : `${activeAction?.action === 'deactivate' ? 'Deactivate' : activeAction?.action} analyst`}
        message={`Confirm this action for ${activeAction?.entry?.displayName || 'this Security Analyst'}.`}
        confirmLabel={activeAction?.decision || activeAction?.action}
        busy={loading}
        onConfirm={handleAction}
        onClose={() => setActiveAction(null)}
      />

      {details ? (
        <div className="modal-backdrop" role="presentation">
          <div className="modal-card" role="dialog" aria-modal="true" aria-labelledby="analyst-detail-title">
            <h3 id="analyst-detail-title">Security Analyst details</h3>
            <dl className="meta-list">
              <div><dt>Display name</dt><dd>{details.displayName || 'Name unavailable'}</dd></div>
              <div><dt>Role</dt><dd>{rolesOf(details).join(', ') || 'Unavailable'}</dd></div>
              <div><dt>Status</dt><dd>{statusLabel(details.status)}</dd></div>
              <div><dt>Registered</dt><dd>{displayDate(details.createdAt)}</dd></div>
            </dl>
            <div className="modal-actions">
              <button type="button" className="secondary-button" onClick={() => setDetails(null)}>Close</button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
