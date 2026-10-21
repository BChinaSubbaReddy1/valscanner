import { useCallback, useEffect, useState } from 'react';
import { organizationApi } from '../../api/client';
import { useAuth } from '../../auth/useAuth';
import ConfirmationDialog from '../../components/ConfirmationDialog';
import LoadingSpinner from '../../components/LoadingSpinner';

export default function OrganizationApprovalPage() {
  const { user } = useAuth();
  const [organizations, setOrganizations] = useState([]);
  const [registry, setRegistry] = useState({ ownOrganization: null, approvedOrganizations: [] });
  const [adminAccounts, setAdminAccounts] = useState({ content: [], totalElements: 0, totalPages: 0, number: 0 });
  const [adminStatus, setAdminStatus] = useState('');
  const [adminPage, setAdminPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [activeDecision, setActiveDecision] = useState(null);
  const [activeDeletion, setActiveDeletion] = useState(null);
  const [activeAdminAction, setActiveAdminAction] = useState(null);

  const loadOrganizations = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [result, registryResult, adminsResult] = await Promise.all([
        organizationApi.listPendingRegistrations(),
        organizationApi.getRegistry(),
        organizationApi.listOrganizationAdmins({
          status: adminStatus || undefined,
          page: adminPage,
          size: 20,
        }),
      ]);
      const list = Array.isArray(result?.data) ? result.data : [];
      const registryData = registryResult?.data || { ownOrganization: null, approvedOrganizations: [] };
      const adminPageData = adminsResult?.data || {};
      let ownOrganization = registryData.ownOrganization;
      if (!ownOrganization && user?.organizationId) {
        try {
          const ownResult = await organizationApi.getOrganization(user.organizationId);
          ownOrganization = { ...ownResult?.data, ownOrganization: true };
        } catch (requestError) {
          setError(`Unable to load your organization metadata: ${requestError.message || 'The request failed.'}`);
        }
      }
      setOrganizations(list);
      setRegistry({ ...registryData, ownOrganization });
      setAdminAccounts({
        content: Array.isArray(adminPageData.content) ? adminPageData.content : [],
        totalElements: Number(adminPageData.totalElements) || 0,
        totalPages: Number(adminPageData.totalPages) || 0,
        number: Number(adminPageData.number) || 0,
      });
      if (!ownOrganization || !user?.organizationId) {
        setError('');
      }
    } catch (requestError) {
      setError(requestError.message || 'Unable to load organization registrations.');
    } finally {
      setLoading(false);
    }
  }, [adminPage, adminStatus, user]);

  useEffect(() => {
    void Promise.resolve().then(loadOrganizations);
  }, [loadOrganizations]);

  const handleDecision = async (organizationId, decision) => {
    if (loading) {
      return;
    }

    try {
      setLoading(true);
      setMessage('');
      setError('');
      const result = await organizationApi.decideRegistration(organizationId, decision);
      const outcome = result?.data?.status;
      const decisionLabel = decision === 'APPROVE' ? 'approved' : 'rejected';
      setMessage(`${result?.message || `The organization ${decisionLabel} request was accepted by the server.`}${outcome ? ` Status: ${outcome}.` : ''}`);
      setActiveDecision(null);
      await loadOrganizations();
    } catch (requestError) {
      setError(requestError.message || 'The organization decision could not be submitted.');
      setLoading(false);
    }
  };

  const handleDeletion = async () => {
    if (!activeDeletion || loading) {
      return;
    }

    try {
      setLoading(true);
      setMessage('');
      setError('');
      const result = await organizationApi.deleteOrganization(activeDeletion.id);
      setMessage(`${result?.message || 'The organization deactivation was accepted by the server.'}${result?.data?.status ? ` Status: ${result.data.status}.` : ''}`);
      setActiveDeletion(null);
      await loadOrganizations();
    } catch (requestError) {
      setError(requestError.message || 'The organization could not be deactivated.');
      setLoading(false);
    }
  };

  const handleAdminAction = async () => {
    if (!activeAdminAction || loading) return;
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const result = await organizationApi.updateOrganizationAdmin(
        activeAdminAction.user.userId,
        activeAdminAction.action,
      );
      const status = result?.data?.status;
      setMessage(`${result?.message || 'Organization Admin account action accepted by the server.'}${status ? ` Status: ${status}.` : ''}`);
      setActiveAdminAction(null);
      await loadOrganizations();
    } catch (requestError) {
      setError(requestError.message || 'The Organization Admin account action could not be completed.');
      setLoading(false);
    }
  };

  const registryOrganizations = [
    ...(registry.ownOrganization ? [registry.ownOrganization] : []),
    ...(registry.approvedOrganizations || []),
  ];

  return (
    <section className="page-shell">
      <div className="page-header">
        <div>
          <p className="eyebrow">Organization approvals</p>
          <h1>Registration requests</h1>
        </div>
      </div>

      {error ? <div className="message-card error">{error}</div> : null}
      {message ? <div className="message-card success">{message}</div> : null}

      <div className="page-header">
        <div>
          <p className="eyebrow">Approved organizations</p>
          <h2>Organization registry</h2>
        </div>
      </div>

      {registryOrganizations.length === 0 ? (
        <div className="empty-state">No approved organizations are available in the registry.</div>
      ) : (
        <div className="card-grid">
          {registryOrganizations.map((organization) => (
            <article className="data-card" key={organization.id}>
              <div className="data-card-header">
                <div>
                  <p className="eyebrow">{organization.ownOrganization ? 'Your organization' : 'Approved organization'}</p>
                  <h3>{organization.name || 'Unnamed organization'}</h3>
                </div>
                <span className="status-chip" data-status={organization.status}>
                  {organization.status || 'Status unavailable'}
                </span>
              </div>
              <dl className="meta-list">
                <div>
                  <dt>Organization Admin</dt>
                  <dd>
                    {organization.adminDisplayName ||
                      [organization.registrationAdminFirstName, organization.registrationAdminLastName].filter(Boolean).join(' ') ||
                      organization.primaryContactName ||
                      'Name unavailable'}
                  </dd>
                </div>
                <div>
                  <dt>Registered</dt>
                  <dd>{organization.registeredAt || organization.createdAt
                    ? new Date(organization.registeredAt || organization.createdAt).toLocaleDateString()
                    : 'Date unavailable'}</dd>
                </div>
                <div>
                  <dt>Approved</dt>
                  <dd>{organization.approvedAt ? new Date(organization.approvedAt).toLocaleDateString() : 'Date unavailable'}</dd>
                </div>
              </dl>
              {!organization.ownOrganization ? (
                <button
                  type="button"
                  className="secondary-button"
                  disabled={loading}
                  onClick={() => setActiveDeletion(organization)}
                >
                  Deactivate organization
                </button>
              ) : null}
            </article>
          ))}
        </div>
      )}

      <section aria-labelledby="organization-admins-heading">
        <div className="page-header">
          <div>
            <p className="eyebrow">Platform administration</p>
            <h2 id="organization-admins-heading">Organization Admin accounts</h2>
          </div>
        </div>
        <div className="user-management-controls">
          <label>
            Filter by account status
            <select
              value={adminStatus}
              onChange={(event) => {
                setAdminStatus(event.target.value);
                setAdminPage(0);
              }}
            >
              <option value="">All eligible statuses</option>
              <option value="ACTIVE">Active</option>
              <option value="SUSPENDED">Suspended</option>
              <option value="DISABLED">Disabled</option>
              <option value="LOCKED">Locked</option>
            </select>
          </label>
        </div>
        {loading && adminAccounts.content.length === 0 ? (
          <LoadingSpinner label="Loading Organization Admin accounts…" />
        ) : adminAccounts.content.length === 0 ? (
          <div className="empty-state">No Organization Admin accounts were returned for this filter.</div>
        ) : (
          <>
            <div className="user-table-scroll">
              <div className="list-table user-management-table" role="table" aria-label="Organization Admin accounts">
                <div className="table-row user-management-row table-row--header" role="row">
                  <span role="columnheader">Display name</span>
                  <span role="columnheader">Role</span>
                  <span role="columnheader">Account status</span>
                  <span role="columnheader">Registered</span>
                  <span role="columnheader">Actions</span>
                </div>
                {adminAccounts.content.map((account) => (
                  <div className="table-row user-management-row" role="row" key={account.userId}>
                    <span role="cell">{account.displayName || 'Name unavailable'}</span>
                    <span role="cell">Organization Admin</span>
                    <span role="cell">
                      <span className="status-chip" data-status={account.status}>{account.status || 'Unavailable'}</span>
                    </span>
                    <span role="cell">{account.createdAt ? new Date(account.createdAt).toLocaleDateString() : 'Date unavailable'}</span>
                    <span role="cell" className="user-management-actions">
                      {account.status === 'ACTIVE' ? (
                        <button type="button" className="secondary-button" disabled={loading} onClick={() => {
                          setActiveAdminAction({ user: account, action: 'suspend' });
                        }}>Suspend</button>
                      ) : null}
                      {account.status === 'SUSPENDED' ? (
                        <button type="button" className="primary-button" disabled={loading} onClick={() => {
                          setActiveAdminAction({ user: account, action: 'restore' });
                        }}>Restore</button>
                      ) : null}
                      {['ACTIVE', 'SUSPENDED'].includes(account.status) ? (
                        <button type="button" className="danger-button" disabled={loading} onClick={() => {
                          setActiveAdminAction({ user: account, action: 'deactivate' });
                        }}>Deactivate</button>
                      ) : null}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            {adminAccounts.totalPages > 1 ? (
              <div className="user-table-pagination">
                <span>{adminAccounts.totalElements} Organization Admin accounts</span>
                <div className="inline-actions">
                  <button type="button" className="secondary-button" disabled={adminPage <= 0 || loading} onClick={() => setAdminPage((current) => current - 1)}>Previous</button>
                  <span>Page {adminAccounts.number + 1} of {adminAccounts.totalPages}</span>
                  <button type="button" className="secondary-button" disabled={adminPage + 1 >= adminAccounts.totalPages || loading} onClick={() => setAdminPage((current) => current + 1)}>Next</button>
                </div>
              </div>
            ) : null}
          </>
        )}
      </section>

      <div className="page-header">
        <div>
          <p className="eyebrow">Organization approvals</p>
          <h2>Pending registration requests</h2>
        </div>
      </div>

      {loading ? (
        <LoadingSpinner label="Loading organization registrations…" />
      ) : organizations.length === 0 ? (
        <div className="empty-state">No pending registrations were returned by the backend.</div>
      ) : (
        <div className="card-grid">
          {organizations.map((organization) => (
            <article className="data-card" key={organization.id || organization.organizationId || organization.name}>
              <div className="data-card-header">
                <div>
                  <p className="eyebrow">Organization</p>
                  <h3>{organization.name || 'Unnamed organization'}</h3>
                </div>
                <span className="status-chip" data-status={organization.status || 'PENDING'}>
                  {organization.status || 'PENDING'}
                </span>
              </div>

              <dl className="meta-list">
                <div>
                  <dt>Primary contact</dt>
                  <dd>{organization.primaryContactName || 'Name unavailable'}</dd>
                </div>
                <div>
                  <dt>Requested</dt>
                  <dd>{organization.createdAt ? new Date(organization.createdAt).toLocaleDateString() : 'Date unavailable'}</dd>
                </div>
              </dl>

              <div className="stack-actions">
                <button type="button" className="primary-button" disabled={loading} onClick={() => {
                  setActiveDecision({ organization, decision: 'APPROVE' });
                }}>
                  Approve
                </button>
                <button type="button" className="secondary-button" disabled={loading} onClick={() => {
                  setActiveDecision({ organization, decision: 'REJECT' });
                }}>
                  Reject
                </button>
              </div>
            </article>
          ))}
        </div>
      )}

      <ConfirmationDialog
        open={Boolean(activeDecision)}
        title={activeDecision?.decision === 'APPROVE' ? 'Approve organization' : 'Reject organization'}
        message={`Are you sure you want to ${activeDecision?.decision?.toLowerCase() || 'review'} the registration for ${activeDecision?.organization?.name || 'this organization'}?`}
        confirmLabel={activeDecision?.decision === 'APPROVE' ? 'Approve' : 'Reject'}
        busy={loading}
        onConfirm={() => handleDecision(activeDecision.organization.id || activeDecision.organization.organizationId, activeDecision.decision)}
        onClose={() => setActiveDecision(null)}
      />

      <ConfirmationDialog
        open={Boolean(activeDeletion)}
        title="Deactivate organization"
        message={`Deactivate ${activeDeletion?.name || 'this organization'}? Its users will lose access, but their accounts and historical records will be retained.`}
        confirmLabel="Deactivate"
        busy={loading}
        onConfirm={handleDeletion}
        onClose={() => setActiveDeletion(null)}
      />

      <ConfirmationDialog
        open={Boolean(activeAdminAction)}
        title={`${activeAdminAction?.action || ''} Organization Admin account`}
        message={`Confirm ${activeAdminAction?.action || 'this action'} for ${activeAdminAction?.user?.displayName || 'this Organization Admin'}.`}
        confirmLabel={activeAdminAction?.action}
        busy={loading}
        onConfirm={handleAdminAction}
        onClose={() => setActiveAdminAction(null)}
      />

    </section>
  );
}
