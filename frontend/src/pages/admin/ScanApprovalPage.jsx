import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { scanApi } from '../../api/client';
import LoadingSpinner from '../../components/LoadingSpinner';

const PAGE_SIZE = 20;

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

function statusText(value) {
  return String(value || 'Unavailable').replace(/_/g, ' ');
}

function dateText(value) {
  if (!value) return 'Not available';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Not available' : date.toLocaleString();
}

export default function ScanApprovalPage() {
  const [requests, setRequests] = useState({ content: [], totalElements: 0, totalPages: 0, number: 0 });
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionError, setActionError] = useState('');
  const [actionId, setActionId] = useState(null);
  const [rejecting, setRejecting] = useState(null);
  const [rejectionReason, setRejectionReason] = useState('');

  const loadRequests = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await scanApi.listPendingApprovals({ page, size: PAGE_SIZE });
      setRequests(pageOf(result));
    } catch (requestError) {
      setError(requestError.message || 'Unable to load scan requests for this organization.');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    void Promise.resolve().then(loadRequests);
  }, [loadRequests]);

  const pendingRequests = requests.content.filter((request) => request.status === 'PENDING_APPROVAL');

  const approve = async (request) => {
    setActionId(request.id);
    setActionError('');
    try {
      await scanApi.approveScan(request.id);
      await loadRequests();
    } catch (requestError) {
      setActionError(requestError.message || 'The scan request could not be approved.');
    } finally {
      setActionId(null);
    }
  };

  const reject = async (request) => {
    if (!rejectionReason.trim()) {
      setActionError('A rejection reason is required.');
      return;
    }
    setActionId(request.id);
    setActionError('');
    try {
      await scanApi.rejectScan(request.id, rejectionReason);
      setRejecting(null);
      setRejectionReason('');
      await loadRequests();
    } catch (requestError) {
      setActionError(requestError.message || 'The scan request could not be rejected.');
    } finally {
      setActionId(null);
    }
  };

  return (
    <section className="page-shell">
      <div className="page-header">
        <div>
          <p className="eyebrow">Organization administration</p>
          <h1>Scan approvals</h1>
          <p className="muted">Review scan requests returned for your organization.</p>
        </div>
        <button type="button" className="secondary-button" onClick={loadRequests} disabled={loading}>Refresh</button>
      </div>

      <div className="card-grid two-up">
        <article className="stat-card">
          <span className="eyebrow">Pending requests on this page</span>
          <strong>{pendingRequests.length}</strong>
        </article>
        <article className="stat-card">
          <span className="eyebrow">Requests returned</span>
          <strong>{requests.totalElements}</strong>
        </article>
      </div>

      {error ? (
        <div className="message-card error" role="alert">
          <p>{error}</p>
          <button type="button" className="secondary-button" onClick={loadRequests}>Retry scan requests</button>
        </div>
      ) : null}
      {actionError ? <div className="message-card error" role="alert">{actionError}</div> : null}

      {loading ? <LoadingSpinner label="Loading scan requests…" /> : error ? null : pendingRequests.length === 0 ? (
        <div className="empty-state">No pending scan requests were returned for this organization.</div>
      ) : (
        <section aria-labelledby="pending-scan-requests-heading">
          <div className="section-header">
            <div>
              <p className="eyebrow">Pending approval</p>
              <h2 id="pending-scan-requests-heading">Scan requests</h2>
            </div>
          </div>
          <div className="card-grid">
            {pendingRequests.map((request) => (
              <article className="data-card" key={request.id}>
                <div className="data-card-header">
                  <div>
                    <p className="eyebrow">Scan request #{request.id}</p>
                    <h3>{request.targetName || `Target ${request.targetId ?? 'unavailable'}`}</h3>
                  </div>
                  <span className="status-chip" data-status={request.status}>{statusText(request.status)}</span>
                </div>
                <dl className="meta-list">
                  <div><dt>Analyst</dt><dd>{request.requestedByDisplayName || 'Name unavailable in backend response'}</dd></div>
                  <div><dt>Scan type</dt><dd>{request.scanType || 'Unavailable'}</dd></div>
                  <div><dt>Submitted</dt><dd>{dateText(request.createdAt)}</dd></div>
                  {request.statusMessage ? <div><dt>Request details</dt><dd>{request.statusMessage}</dd></div> : null}
                  {request.rejectionReason ? <div><dt>Rejection reason</dt><dd>{request.rejectionReason}</dd></div> : null}
                </dl>
                <div className="inline-actions">
                <Link className="secondary-button" to={`/admin/scans/${request.id}`}>View details</Link>
                <button type="button" className="primary-button" disabled={actionId != null} onClick={() => approve(request)}>
                  {actionId === request.id ? 'Approving…' : 'Approve'}
                </button>
                <button type="button" className="danger-button" disabled={actionId != null} onClick={() => setRejecting(request)}>
                  Reject
                </button>
                </div>
                {rejecting?.id === request.id ? (
                <div className="field rejection-field">
                  <label htmlFor={`rejection-reason-${request.id}`}>Rejection reason
                    <textarea id={`rejection-reason-${request.id}`} value={rejectionReason} onChange={(event) => setRejectionReason(event.target.value)} maxLength={1000} />
                  </label>
                  <div className="inline-actions">
                    <button type="button" className="danger-button" disabled={actionId != null} onClick={() => reject(request)}>Confirm rejection</button>
                    <button type="button" className="secondary-button" disabled={actionId != null} onClick={() => { setRejecting(null); setRejectionReason(''); }}>Cancel</button>
                  </div>
                </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      )}

      {requests.totalPages > 1 ? (
        <div className="user-table-pagination">
          <span>{requests.totalElements} requests</span>
          <div className="inline-actions">
            <button type="button" className="secondary-button" disabled={page <= 0 || loading} onClick={() => setPage((current) => current - 1)}>Previous</button>
            <span>Page {requests.number + 1} of {requests.totalPages}</span>
            <button type="button" className="secondary-button" disabled={page + 1 >= requests.totalPages || loading} onClick={() => setPage((current) => current + 1)}>Next</button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
