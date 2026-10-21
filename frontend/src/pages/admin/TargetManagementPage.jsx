import { useCallback, useEffect, useState } from 'react';
import { targetApi } from '../../api/client';
import ConfirmationDialog from '../../components/ConfirmationDialog';
import LoadingSpinner from '../../components/LoadingSpinner';

const EMPTY_FORM = { name: '', url: '', type: 'WEB_APPLICATION' };
const TARGET_TYPES = ['WEB_APPLICATION', 'API', 'MOBILE', 'NETWORK', 'OTHER'];

function dataOf(response) {
  return response?.data ?? response;
}

function targetList(response) {
  const data = dataOf(response);
  return Array.isArray(data) ? data : [];
}

export default function TargetManagementPage() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [activeDecision, setActiveDecision] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState('');

  const loadTargets = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setTargets(targetList(await targetApi.listTargets()));
    } catch (requestError) {
      setError(requestError.message || 'Unable to load organization targets.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(loadTargets);
  }, [loadTargets]);

  const handleCreate = async (event) => {
    event.preventDefault();
    if (!form.name.trim() || !form.url.trim()) {
      setFormError('Name and URL are required.');
      return;
    }

    setSubmitting(true);
    setFormError('');
    setError('');
    setMessage('');
    try {
      const result = await targetApi.createTarget({
        name: form.name.trim(),
        url: form.url.trim(),
        type: form.type,
      });
      setMessage(result?.message || 'Target creation was accepted by the server.');
      setForm(EMPTY_FORM);
      setShowCreateForm(false);
      await loadTargets();
    } catch (requestError) {
      setFormError(requestError.message || 'The target could not be created.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDecision = async () => {
    if (!activeDecision || loading) return;
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const result = await targetApi.decideTarget(activeDecision.target.id, activeDecision.decision);
      setMessage(result?.message || `Target ${activeDecision.decision.toLowerCase()} decision was accepted by the server.`);
      setActiveDecision(null);
      await loadTargets();
    } catch (requestError) {
      setError(requestError.message || 'The target decision could not be submitted.');
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget || loading) return;
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const result = await targetApi.deleteTarget(deleteTarget.id);
      setMessage(`${result?.message || 'Target deactivation was accepted by the server.'}${dataOf(result)?.status ? ` Status: ${dataOf(result).status}.` : ''}`);
      setDeleteTarget(null);
      await loadTargets();
    } catch (requestError) {
      setError(requestError.message || 'The target could not be deactivated.');
      setLoading(false);
    }
  };

  return (
    <section className="page-shell">
      <div className="page-header">
        <div>
          <p className="eyebrow">Authorized workspace</p>
          <h1>Target management</h1>
        </div>
        <div className="inline-actions">
          <button type="button" className="secondary-button" onClick={loadTargets} disabled={loading}>
            Refresh
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={() => {
              setShowCreateForm((visible) => !visible);
              setFormError('');
            }}
            disabled={loading}
          >
            {showCreateForm ? 'Cancel' : '+ Add target'}
          </button>
        </div>
      </div>

      {showCreateForm ? (
        <div className="data-card" style={{ marginBottom: '1.5rem' }}>
          <h3>New target</h3>
          <form onSubmit={handleCreate} className="form-grid" noValidate style={{ marginTop: '1rem' }}>
            <label>
              Name
              <input
                type="text"
                name="name"
                value={form.name}
                onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                maxLength={150}
                aria-label="Target name"
              />
            </label>
            <label>
              URL
              <input
                type="url"
                name="url"
                value={form.url}
                onChange={(event) => setForm((current) => ({ ...current, url: event.target.value }))}
                maxLength={2048}
                placeholder="https://example.com"
                aria-label="Target URL"
              />
            </label>
            <label>
              Type
              <select
                name="type"
                value={form.type}
                onChange={(event) => setForm((current) => ({ ...current, type: event.target.value }))}
                aria-label="Target type"
              >
                {TARGET_TYPES.map((type) => <option key={type} value={type}>{type.replace(/_/g, ' ')}</option>)}
              </select>
            </label>
            {formError ? <div className="message-card error" role="alert">{formError}</div> : null}
            <div className="stack-actions">
              <button type="submit" className="primary-button" disabled={submitting}>
                {submitting ? 'Creating…' : 'Create target'}
              </button>
            </div>
          </form>
        </div>
      ) : null}

      {error ? <div className="message-card error" role="alert">{error}</div> : null}
      {message ? <div className="message-card success" role="status">{message}</div> : null}

      {loading ? (
        <LoadingSpinner label="Loading targets…" />
      ) : targets.length === 0 ? (
        <div className="empty-state">No targets are currently available for this organization.</div>
      ) : (
        <div className="card-grid">
          {targets.map((target) => (
            <article className="data-card" key={target.id}>
              <div className="data-card-header">
                <div>
                  <p className="eyebrow">Organization target</p>
                  <h3>{target.name}</h3>
                </div>
                <span className="status-chip" data-status={target.status}>{target.status}</span>
              </div>
              <dl className="meta-list">
                <div><dt>Type</dt><dd>{target.type?.replace(/_/g, ' ') || 'Unavailable'}</dd></div>
                <div><dt>URL</dt><dd className="target-url">{target.url || 'Unavailable'}</dd></div>
                {target.createdAt ? (
                  <div><dt>Created</dt><dd>{new Date(target.createdAt).toLocaleString()}</dd></div>
                ) : null}
                {target.updatedAt ? (
                  <div><dt>Updated</dt><dd>{new Date(target.updatedAt).toLocaleString()}</dd></div>
                ) : null}
              </dl>

              {target.status === 'PENDING' ? (
                <div className="stack-actions">
                  <button type="button" className="primary-button" disabled={loading} onClick={() => {
                    setActiveDecision({ target, decision: 'APPROVE' });
                  }}>Approve</button>
                  <button type="button" className="secondary-button" disabled={loading} onClick={() => {
                    setActiveDecision({ target, decision: 'REJECT' });
                  }}>Reject</button>
                </div>
              ) : null}
              {target.status !== 'DELETED' ? (
                <div className="stack-actions">
                  <button type="button" className="danger-button" disabled={loading} onClick={() => setDeleteTarget(target)}>
                    Deactivate
                  </button>
                </div>
              ) : null}
            </article>
          ))}
        </div>
      )}

      <ConfirmationDialog
        open={Boolean(activeDecision)}
        title={`${activeDecision?.decision === 'APPROVE' ? 'Approve' : 'Reject'} target`}
        message={`Confirm ${activeDecision?.decision?.toLowerCase() || 'this decision'} for "${activeDecision?.target?.name || 'this target'}".`}
        confirmLabel={activeDecision?.decision}
        busy={loading}
        onConfirm={handleDecision}
        onClose={() => setActiveDecision(null)}
      />

      <ConfirmationDialog
        open={Boolean(deleteTarget)}
        title="Deactivate target"
        message={`Deactivate "${deleteTarget?.name || 'this target'}"? The backend retains the target and changes its lifecycle status.`}
        confirmLabel="Deactivate"
        busy={loading}
        onConfirm={handleDelete}
        onClose={() => setDeleteTarget(null)}
      />
    </section>
  );
}
