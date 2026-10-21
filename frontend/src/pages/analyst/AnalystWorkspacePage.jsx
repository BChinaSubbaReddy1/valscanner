import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { scanApi, targetApi } from '../../api/client';
import { useAuth } from '../../auth/useAuth';
import LoadingSpinner from '../../components/LoadingSpinner';
import { hasRole } from '../../utils/permissions';

const SCAN_TYPE = 'PASSIVE_HEADERS';
const ACTIVE_SCAN_STATUSES = ['PENDING_APPROVAL', 'CREATED', 'QUEUED', 'CRAWLING', 'SCANNING', 'RUNNING'];
const CANCELLABLE_SCAN_STATUSES = ['PENDING_APPROVAL', 'CREATED', 'QUEUED', 'CRAWLING', 'SCANNING', 'RUNNING'];
const POLL_INTERVAL_MS = 5000;
const MAX_POLL_ATTEMPTS = 60;
const PAGE_SIZE = 10;

function dataOf(response) {
  return response?.data ?? response;
}

function displayName(user) {
  return user?.displayName || user?.fullName || user?.name ||
    [user?.firstName, user?.lastName].filter(Boolean).join(' ') || 'Security Analyst';
}

function statusText(value) {
  return value ? String(value).replace(/_/g, ' ') : 'Not provided by the authenticated profile.';
}

function dateText(value) {
  if (!value) return 'Not available';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Not available' : date.toLocaleString();
}

function isApprovedAnalyst(user) {
  return hasRole(user, 'SECURITY_ANALYST') &&
    user?.accountStatus === 'ACTIVE' &&
    user?.membershipApprovalStatus === 'APPROVED' &&
    user?.organizationStatus === 'APPROVED';
}

function approvalMessage(user) {
  if (!user?.accountStatus || !user?.membershipApprovalStatus || !user?.organizationStatus) {
    return 'Scan access is unavailable because the authenticated profile did not return complete account and organization approval status.';
  }
  if (user.accountStatus !== 'ACTIVE') {
    return `Scan access requires an active account. Current account status: ${statusText(user.accountStatus)}.`;
  }
  if (user.membershipApprovalStatus !== 'APPROVED') {
    return `Scan access requires approved organization membership. Current membership status: ${statusText(user.membershipApprovalStatus)}.`;
  }
  if (user.organizationStatus !== 'APPROVED') {
    return `Scan access requires an approved organization. Current organization status: ${statusText(user.organizationStatus)}.`;
  }
  return '';
}

function jobListOf(response) {
  const data = dataOf(response);
  return {
    content: Array.isArray(data?.content) ? data.content : [],
    totalPages: Number(data?.totalPages) || 0,
    totalElements: Number(data?.totalElements) || 0,
    number: Number(data?.number) || 0,
  };
}

function aggregateCount(stats, fields) {
  if (!stats || fields.some((field) => !Number.isFinite(Number(stats[field])))) {
    return null;
  }
  return fields.reduce((total, field) => total + Number(stats[field]), 0);
}

export default function AnalystWorkspacePage() {
  const { user, refreshUser } = useAuth();
  const [profileReady, setProfileReady] = useState(false);
  const [profileError, setProfileError] = useState('');
  const canUseScanner = profileReady && isApprovedAnalyst(user);
  const [targets, setTargets] = useState([]);
  const [loadingTargets, setLoadingTargets] = useState(true);
  const [targetError, setTargetError] = useState('');
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [scans, setScans] = useState({ content: [], totalPages: 0, totalElements: 0, number: 0 });
  const [scanPage, setScanPage] = useState(0);
  const [loadingScans, setLoadingScans] = useState(true);
  const [scanError, setScanError] = useState('');
  const [scanMessage, setScanMessage] = useState('');
  const [submittingTarget, setSubmittingTarget] = useState(null);
  const [cancellingScan, setCancellingScan] = useState(null);
  const [pollingPaused, setPollingPaused] = useState(false);
  const [dashboardFindings, setDashboardFindings] = useState([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState('');
  const [dashboardStats, setDashboardStats] = useState(null);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [dashboardError, setDashboardError] = useState('');
  const submissionLock = useRef(false);
  const scanLoadLock = useRef(false);
  const pollingAttempts = useRef(0);

  useEffect(() => {
    let mounted = true;
    refreshUser()
      .catch((requestError) => {
        if (mounted) setProfileError(requestError.message || 'Unable to verify analyst account approval.');
      })
      .finally(() => {
        if (mounted) setProfileReady(true);
      });
    return () => {
      mounted = false;
    };
  }, [refreshUser]);

  const loadTargets = useCallback(async () => {
    if (!canUseScanner) return;
    setLoadingTargets(true);
    setTargetError('');
    try {
      const result = await targetApi.listTargets();
      const data = dataOf(result);
      setTargets(Array.isArray(data) ? data : []);
    } catch (requestError) {
      setTargetError(requestError.message || 'Unable to load targets authorized for this analyst.');
    } finally {
      setLoadingTargets(false);
    }
  }, [canUseScanner]);

  const loadDashboard = useCallback(async () => {
    if (!canUseScanner) return;
    setDashboardLoading(true);
    setDashboardError('');
    try {
      setDashboardStats(dataOf(await scanApi.getAnalystDashboard()) || {});
    } catch (requestError) {
      setDashboardError(requestError.message || 'Unable to load analyst dashboard statistics.');
    } finally {
      setDashboardLoading(false);
    }
  }, [canUseScanner]);

  const loadScans = useCallback(async ({ quiet = false, page = scanPage } = {}) => {
    if (!canUseScanner || scanLoadLock.current) return;
    if (!quiet) {
      pollingAttempts.current = 0;
      setPollingPaused(false);
    }
    scanLoadLock.current = true;
    if (!quiet) setLoadingScans(true);
    setScanError('');
    try {
      setScans(jobListOf(await scanApi.listScans({ page, size: PAGE_SIZE })));
    } catch (requestError) {
      setScanError(requestError.message || 'Unable to load scan history.');
    } finally {
      scanLoadLock.current = false;
      if (!quiet) setLoadingScans(false);
    }
  }, [canUseScanner, scanPage]);

  useEffect(() => {
    if (!canUseScanner) return;
    void Promise.resolve().then(() => {
      void loadTargets();
      void loadScans();
      void loadDashboard();
    });
  }, [canUseScanner, loadDashboard, loadScans, loadTargets]);

  useEffect(() => {
    if (!canUseScanner) return undefined;
    const completedScans = scans.content.filter((scan) => scan.status === 'COMPLETED');
    let mounted = true;
    if (completedScans.length === 0) {
      Promise.resolve().then(() => {
        if (mounted) {
          setDashboardFindings([]);
          setFindingsError('');
        }
      });
      return () => {
        mounted = false;
      };
    }
    Promise.resolve().then(() => {
      if (mounted) {
        setFindingsLoading(true);
        setFindingsError('');
      }
    });
    Promise.all(completedScans.map(async (scan) => {
      try {
        const response = await scanApi.listFindings(scan.id);
        const findingsForScan = dataOf(response);
        return (Array.isArray(findingsForScan) ? findingsForScan : [])
          .map((finding) => ({ ...finding, scanId: scan.id, targetName: scan.targetName }));
      } catch (requestError) {
        if (mounted) setFindingsError(requestError.message || 'Unable to load recent findings.');
        return [];
      }
    })).then((groups) => {
      if (mounted) setDashboardFindings(groups.flat());
    }).finally(() => {
      if (mounted) setFindingsLoading(false);
    });
    return () => {
      mounted = false;
    };
  }, [canUseScanner, scans.content]);

  const hasActiveScans = scans.content.some((scan) => ACTIVE_SCAN_STATUSES.includes(scan.status));
  const severityCounts = useMemo(() => dashboardFindings.reduce((counts, finding) => {
    const severity = String(finding.severity || 'UNKNOWN').toUpperCase();
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, {}), [dashboardFindings]);
  const activeJobCount = aggregateCount(dashboardStats, [
    'queuedScans',
    'crawlingScans',
    'scanningScans',
    'runningScans',
  ]);
  const selectedTarget = targets.find((target) => String(target.id) === String(selectedTargetId));
  useEffect(() => {
    if (!canUseScanner || !hasActiveScans) return undefined;
    if (pollingAttempts.current >= MAX_POLL_ATTEMPTS) {
      setPollingPaused(true);
      return undefined;
    }
    const timer = window.setInterval(() => {
      pollingAttempts.current += 1;
      void loadScans({ quiet: true });
      if (pollingAttempts.current >= MAX_POLL_ATTEMPTS) {
        setPollingPaused(true);
        window.clearInterval(timer);
      }
    }, POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [canUseScanner, hasActiveScans, loadScans]);

  const startScan = async (target) => {
    if (!canUseScanner || target.status !== 'APPROVED' || submissionLock.current) return;
    submissionLock.current = true;
    pollingAttempts.current = 0;
    setPollingPaused(false);
    setSubmittingTarget(target.id);
    setScanError('');
    setScanMessage('');
    try {
      const result = await scanApi.createScan(target.id, SCAN_TYPE);
      const createdJob = dataOf(result);
      if (!createdJob || createdJob.id == null) {
        throw new Error('The backend response did not include a scan job.');
      }
      setScanMessage(result?.message || `Scan job ${createdJob.id} was created by the backend.`);
      setScans((current) => ({
        ...current,
        content: [createdJob, ...current.content.filter((scan) => scan.id !== createdJob.id)].slice(0, PAGE_SIZE),
      }));
      setScanPage(0);
      await loadScans({ quiet: true, page: 0 });
    } catch (requestError) {
      setScanError(requestError.message || 'The scan could not be started.');
    } finally {
      submissionLock.current = false;
      setSubmittingTarget(null);
    }
  };

  const cancelScan = async (scan) => {
    if (
      !canUseScanner ||
      !CANCELLABLE_SCAN_STATUSES.includes(scan.status) ||
      scan.cancellationRequested ||
      cancellingScan != null
    ) return;
    setCancellingScan(scan.id);
    setScanError('');
    setScanMessage('');
    try {
      const result = await scanApi.cancelScan(scan.id);
      const job = dataOf(result);
      setScans((current) => ({
        ...current,
        content: current.content.map((entry) => entry.id === job.id ? job : entry),
      }));
      setScanMessage(result?.message || `Scan job ${job.id} cancellation was recorded by the backend.`);
      await loadScans({ quiet: true });
    } catch (requestError) {
      setScanError(requestError.message || 'The scan could not be cancelled.');
    } finally {
      setCancellingScan(null);
    }
  };

  return (
    <section className="page-shell analyst-page">
      <div className="page-header analyst-hero">
        <div>
          <p className="eyebrow">Security operations overview</p>
          <h1>Good to see you, {displayName(user)}</h1>
          <p className="muted">Monitor approved targets, launch passive header scans, and review persisted findings.</p>
        </div>
        <a className="primary-button" href="#targets">Start a scan</a>
      </div>

      <div className="analyst-stat-grid" aria-label="Scan overview">
        <article className="stat-card analyst-stat-card"><span className="eyebrow">Total scans</span><strong>{scans.totalElements}</strong><span className="muted">Returned by the backend</span></article>
        <article className="stat-card analyst-stat-card"><span className="eyebrow">Active jobs</span><strong>{dashboardLoading ? '—' : activeJobCount ?? 'Unavailable'}</strong><span className="muted">Backend aggregate</span></article>
        <article className="stat-card analyst-stat-card"><span className="eyebrow">Approved targets</span><strong>{dashboardLoading ? '—' : dashboardStats?.approvedTargets ?? 'Unavailable'}</strong><span className="muted">Backend aggregate</span></article>
        <article className="stat-card analyst-stat-card"><span className="eyebrow">Findings loaded</span><strong>{findingsLoading ? '—' : dashboardFindings.length}</strong><span className="muted">From completed scans</span></article>
      </div>

      {!profileReady ? <LoadingSpinner label="Verifying account and organization approval…" /> : null}
      {profileError ? <div className="message-card error" role="alert">{profileError}</div> : null}
      {dashboardError ? (
        <div className="message-card error" role="alert">
          <p>{dashboardError}</p>
          {canUseScanner ? <button type="button" className="secondary-button" onClick={loadDashboard}>Retry dashboard statistics</button> : null}
        </div>
      ) : null}
      {profileReady && !profileError && !canUseScanner ? (
        <div className="message-card error" role="status">{approvalMessage(user)}</div>
      ) : null}

      <section id="targets" aria-labelledby="authorized-targets-heading" className="analyst-section">
        <div className="page-header">
          <div>
            <p className="eyebrow">Approved and authorized resources</p>
            <h2 id="authorized-targets-heading">Available targets</h2>
          </div>
          {canUseScanner ? (
            <button type="button" className="secondary-button" onClick={loadTargets} disabled={loadingTargets}>
              Refresh targets
            </button>
          ) : null}
        </div>
        {targetError ? (
        <div className="message-card error" role="alert">
          <p>{targetError}</p>
          {canUseScanner ? <button type="button" className="secondary-button" onClick={loadTargets}>Retry targets</button> : null}
        </div>
        ) : null}
        {loadingTargets && canUseScanner ? (
          <LoadingSpinner label="Loading approved targets…" />
        ) : targetError ? null : targets.length === 0 ? (
          <div className="empty-state">No approved targets are currently available to this analyst.</div>
        ) : (
          <>
            <article id="request-scan" className="data-card scan-launch-card">
              <div>
                <p className="eyebrow">New scan</p>
                <h3>Run a passive header scan</h3>
                <p className="muted">Choose an approved target. The backend currently supports PASSIVE_HEADERS only.</p>
              </div>
              <div className="scan-launch-controls">
                <label htmlFor="scan-target-select">Approved target
                  <select id="scan-target-select" value={selectedTargetId} onChange={(event) => setSelectedTargetId(event.target.value)}>
                    <option value="">Select a target</option>
                    {targets.filter((target) => target.status === 'APPROVED').map((target) => (
                      <option key={target.id} value={target.id}>{target.name || target.url || `Target ${target.id}`}</option>
                    ))}
                  </select>
                </label>
                <div className="scan-config-summary">
                  <span>Scan type</span><strong>PASSIVE_HEADERS</strong>
                </div>
                <button type="button" className="primary-button" disabled={!selectedTarget || submittingTarget != null} onClick={() => startScan(selectedTarget)}>
                  {submittingTarget === selectedTarget?.id ? 'Starting scan…' : 'Start selected scan'}
                </button>
              </div>
            </article>
            <div className="card-grid">
            {targets.map((target) => (
              <article className="data-card" key={target.id}>
                <div className="data-card-header">
                  <div>
                    <p className="eyebrow">Authorized target</p>
                    <h3>{target.name || 'Unnamed target'}</h3>
                  </div>
                  <span className="status-chip" data-status={target.status}>{target.status || 'Unavailable'}</span>
                </div>
                <dl className="meta-list">
                  <div><dt>Type</dt><dd>{target.type?.replace(/_/g, ' ') || 'Unavailable'}</dd></div>
                  <div><dt>URL</dt><dd className="target-url">{target.url || 'Unavailable'}</dd></div>
                </dl>
                {canUseScanner && target.status === 'APPROVED' ? (
                  <button
                    type="button"
                    className="primary-button"
                    disabled={submittingTarget != null}
                    onClick={() => startScan(target)}
                  >
                    {submittingTarget === target.id ? 'Starting scan…' : 'Run scan'}
                  </button>
                ) : null}
              </article>
            ))}
            </div>
          </>
        )}
        <p className="muted">
          The backend returns approved targets within the authenticated analyst&apos;s organization and independently enforces scan authorization.
        </p>
      </section>

      <section id="history" aria-labelledby="scan-history-heading" className="analyst-section">
        <div className="page-header">
          <div>
            <p className="eyebrow">Backend scan jobs</p>
            <h2 id="scan-history-heading">Scan queue and history</h2>
          </div>
          {canUseScanner ? (
            <button type="button" className="secondary-button" onClick={() => loadScans()} disabled={loadingScans}>
              Refresh scans
            </button>
          ) : null}
        </div>
        {scanError ? (
          <div className="message-card error" role="alert">
            <p>{scanError}</p>
            {canUseScanner ? <button type="button" className="secondary-button" onClick={() => loadScans()}>Retry scan history</button> : null}
          </div>
        ) : null}
        {scanMessage ? <div className="message-card success" role="status">{scanMessage}</div> : null}
        {pollingPaused ? (
          <div className="message-card" role="status">
            Automatic status refresh paused after five minutes. Refresh scan history to check the backend status again.
          </div>
        ) : null}
        {loadingScans && canUseScanner ? (
          <LoadingSpinner label="Loading scan history…" />
        ) : scanError ? null : scans.content.length === 0 ? (
          <div className="empty-state">No scan jobs were returned for this organization.</div>
        ) : (
          <>
            <div className="card-grid">
              {scans.content.map((scan) => (
                <article className="data-card" key={scan.id}>
                  <div className="data-card-header">
                    <div>
                      <p className="eyebrow">{scan.scanType || 'Scan type unavailable'}</p>
                      <h3>{scan.targetName || `Target ${scan.targetId ?? 'unavailable'}`}</h3>
                    </div>
                    <span className="status-chip" data-status={scan.status} aria-label={`Scan status: ${scan.status}`}>{scan.status || 'UNKNOWN STATUS'}</span>
                  </div>
                  <dl className="meta-list">
                    {Number.isFinite(scan.progress) ? <div><dt>Progress</dt><dd>{scan.progress}%</dd></div> : null}
                    <div><dt>Created</dt><dd>{dateText(scan.createdAt)}</dd></div>
                    {scan.startedAt ? <div><dt>Started</dt><dd>{dateText(scan.startedAt)}</dd></div> : null}
                    {scan.completedAt ? <div><dt>Completed</dt><dd>{dateText(scan.completedAt)}</dd></div> : null}
                    {scan.statusMessage ? <div><dt>Status details</dt><dd>{scan.statusMessage}</dd></div> : null}
                    {scan.reviewedAt ? <div><dt>Decision time</dt><dd>{dateText(scan.reviewedAt)}</dd></div> : null}
                    {scan.rejectionReason ? <div><dt>Rejection reason</dt><dd>{scan.rejectionReason}</dd></div> : null}
                    {scan.status === 'FAILED' && scan.failureReason ? (
                      <div><dt>Failure details</dt><dd>{scan.failureReason}</dd></div>
                    ) : null}
                  </dl>
                  <div className="inline-actions">
                    <Link className="secondary-button" to={`/analyst/scans/${scan.id}`}>Scan details and findings</Link>
                    {CANCELLABLE_SCAN_STATUSES.includes(scan.status) && !scan.cancellationRequested ? (
                      <button
                        type="button"
                        className="danger-button"
                        disabled={cancellingScan != null}
                        onClick={() => cancelScan(scan)}
                      >
                        {cancellingScan === scan.id ? 'Cancelling…' : 'Cancel scan'}
                      </button>
                    ) : null}
                  </div>
                </article>
              ))}
            </div>
            {scans.totalPages > 1 ? (
              <div className="user-table-pagination">
                <span>{scans.totalElements} scan jobs</span>
                <div className="inline-actions">
                  <button type="button" className="secondary-button" disabled={scanPage <= 0 || loadingScans} onClick={() => setScanPage((current) => current - 1)}>Previous</button>
                  <span>Page {scans.number + 1} of {scans.totalPages}</span>
                  <button type="button" className="secondary-button" disabled={scanPage + 1 >= scans.totalPages || loadingScans} onClick={() => setScanPage((current) => current + 1)}>Next</button>
                </div>
              </div>
            ) : null}
          </>
        )}
        <p className="muted">
          History is returned by the backend for this approved organization; scan access and cross-organization isolation are enforced by the server.
        </p>
      </section>

      <section id="findings" aria-labelledby="recent-findings-heading" className="analyst-section">
        <div className="page-header">
          <div>
            <p className="eyebrow">Persisted scan output</p>
            <h2 id="recent-findings-heading">Recent findings</h2>
          </div>
          <div className="severity-summary" aria-label="Finding severity summary">
            {Object.entries(severityCounts).map(([severity, count]) => <span key={severity} className="severity-summary-item"><b data-severity={severity}>{count}</b>{severity.replace(/_/g, ' ')}</span>)}
          </div>
        </div>
        {findingsError ? <div className="message-card error" role="alert">{findingsError}</div> : null}
        {findingsLoading ? <LoadingSpinner label="Loading recent findings…" /> : findingsError ? null : dashboardFindings.length === 0 ? (
          <div className="empty-state">No findings were returned by completed scans on this page.</div>
        ) : (
          <div className="finding-list">
            {dashboardFindings.slice(0, 5).map((finding) => (
              <article className="finding-row" key={`${finding.scanId}-${finding.id}`}>
                <span className="severity-dot" data-severity={finding.severity} aria-label={`${finding.severity || 'Unknown'} severity`} />
                <div><strong>{finding.checkType || 'Finding type unavailable'}</strong><span>{finding.targetName || 'Target unavailable'}</span></div>
                <span className="finding-severity">{finding.severity || 'Severity unavailable'}</span>
                <time dateTime={finding.detectedAt || undefined}>{dateText(finding.detectedAt)}</time>
                <Link className="secondary-button compact-button" to={`/analyst/scans/${finding.scanId}`}>View scan</Link>
              </article>
            ))}
          </div>
        )}
      </section>
    </section>
  );
}
