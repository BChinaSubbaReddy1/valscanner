import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { scanApi } from '../../api/client';
import { useAuth } from '../../auth/useAuth';
import LoadingSpinner from '../../components/LoadingSpinner';
import { hasRole } from '../../utils/permissions';

const ACTIVE_STATUSES = ['PENDING_APPROVAL', 'CREATED', 'QUEUED', 'CRAWLING', 'SCANNING', 'RUNNING'];
const CANCELLABLE_STATUSES = ['PENDING_APPROVAL', 'CREATED', 'QUEUED', 'CRAWLING', 'SCANNING', 'RUNNING'];
const POLL_INTERVAL_MS = 5000;
const MAX_POLL_ATTEMPTS = 60;

function dataOf(response) {
  return response?.data ?? response;
}

function dateText(value) {
  if (!value) return 'Not available';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Not available' : date.toLocaleString();
}

function statusText(value) {
  return String(value || 'Unavailable').replace(/_/g, ' ');
}

function detectionSourceLabel(source) {
  if (!source) return 'Source unavailable';
  if (source === 'ZAP' || source.startsWith('ZAP_')) return 'OWASP ZAP';
  if (source === 'PASSIVE_HEADERS') return 'Native Header Engine';
  if (source === 'ACTIVE_QUERY_PARAMETER') return 'Native Active Probe';
  if (source === 'NVD_CVE_LOOKUP') return 'NVD CVE Lookup';
  return String(source).replace(/_/g, ' ');
}

function canViewScanForUser(user) {
  if (hasRole(user, 'ADMIN')) return true;
  return hasRole(user, 'SECURITY_ANALYST') &&
    user?.accountStatus === 'ACTIVE' &&
    user?.membershipApprovalStatus === 'APPROVED' &&
    user?.organizationStatus === 'APPROVED';
}

function parseCveEvidence(evidence) {
  if (!evidence || typeof evidence !== 'string') return null;
  // Conservative parser matching: matches (CVE-\d{4}-\d{4,7}) \(CVSS score: ([0-9.]+), severity: ([A-Za-z]+), vector: ([^)]+)\)
  const cveMatch = evidence.match(/\b(CVE-\d{4}-\d{4,7})\b/i);
  if (!cveMatch) return null;
  const cveId = cveMatch[1].toUpperCase();

  const scoreMatch = evidence.match(/CVSS score:\s*([0-9.]+)/i);
  const cvssScore = scoreMatch ? scoreMatch[1] : null;

  const severityMatch = evidence.match(/severity:\s*([A-Za-z]+)/i);
  const cvssSeverity = severityMatch ? severityMatch[1].toUpperCase() : null;

  const vectorMatch = evidence.match(/vector:\s*([^)]+)\)/i);
  const cvssVector = vectorMatch ? vectorMatch[1].trim() : null;

  return {
    cveId,
    cvssScore,
    cvssSeverity,
    cvssVector,
  };
}

export default function ScanDetailsPage() {
  const { scanId } = useParams();
  const { user, refreshUser } = useAuth();
  const [profileReady, setProfileReady] = useState(false);
  const [profileError, setProfileError] = useState('');
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [crawlPages, setCrawlPages] = useState([]);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [crawlPagesLoading, setCrawlPagesLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [error, setError] = useState('');
  const [findingsError, setFindingsError] = useState('');
  const [crawlPagesError, setCrawlPagesError] = useState('');
  const [reportError, setReportError] = useState('');
  const [exportError, setExportError] = useState('');
  const [exportingFormat, setExportingFormat] = useState(null);
  const [actionError, setActionError] = useState('');
  const [cancelling, setCancelling] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [pollingPaused, setPollingPaused] = useState(false);
  const pollingAttempts = useRef(0);
  const scanLoadLock = useRef(false);
  const canViewScan = profileReady && canViewScanForUser(user);

  useEffect(() => {
    let mounted = true;
    refreshUser()
      .catch((requestError) => {
        if (mounted) setProfileError(requestError.message || 'Unable to verify account access.');
      })
      .finally(() => {
        if (mounted) setProfileReady(true);
      });
    return () => {
      mounted = false;
    };
  }, [refreshUser]);

  const loadScan = useCallback(async ({ quiet = false } = {}) => {
    if (!canViewScan || scanLoadLock.current) return;
    scanLoadLock.current = true;
    if (!quiet) {
      pollingAttempts.current = 0;
      setPollingPaused(false);
    }
    if (!quiet) setLoading(true);
    setError('');
    try {
      const result = await scanApi.getScan(scanId);
      const job = dataOf(result);
      setScan(job);
      setCrawlPagesLoading(true);
      try {
        const crawlPagesResult = await scanApi.listCrawlPages(scanId);
        const data = dataOf(crawlPagesResult);
        setCrawlPages(Array.isArray(data) ? data : []);
        setCrawlPagesError('');
      } catch (requestError) {
        setCrawlPages([]);
        setCrawlPagesError(requestError.message || 'Unable to load crawl pages for this scan.');
      } finally {
        setCrawlPagesLoading(false);
      }
      if (job?.status === 'COMPLETED') {
        setFindingsLoading(true);
        try {
          const findingsResult = await scanApi.listFindings(scanId);
          const data = dataOf(findingsResult);
          setFindings(Array.isArray(data) ? data : []);
          setFindingsError('');
        } catch (requestError) {
          setFindings([]);
          setFindingsError(requestError.message || 'Unable to load findings for this scan.');
        } finally {
          setFindingsLoading(false);
        }
      } else {
        setFindings([]);
        setFindingsError('');
      }

      // Load report data (supported for any accessible scan status)
      setReportLoading(true);
      try {
        const reportResult = await scanApi.getReport(scanId);
        const reportData = dataOf(reportResult);
        setReport(reportData || null);
        setReportError('');
      } catch (requestError) {
        setReport(null);
        setReportError(requestError.message || 'Unable to load scan report.');
      } finally {
        setReportLoading(false);
      }
    } catch (requestError) {
      setScan(null);
      setFindings([]);
      setCrawlPages([]);
      setReport(null);
      setError(requestError.message || 'Unable to load this scan. It may not be available to your organization.');
    } finally {
      scanLoadLock.current = false;
      if (!quiet) setLoading(false);
    }
  }, [canViewScan, scanId]);

  useEffect(() => {
    void Promise.resolve().then(() => loadScan());
  }, [loadScan]);

  useEffect(() => {
    if (!ACTIVE_STATUSES.includes(scan?.status) || !canViewScan) return undefined;
    if (pollingAttempts.current >= MAX_POLL_ATTEMPTS) {
      setPollingPaused(true);
      return undefined;
    }
    const timer = window.setInterval(() => {
      pollingAttempts.current += 1;
      void loadScan({ quiet: true });
      if (pollingAttempts.current >= MAX_POLL_ATTEMPTS) {
        setPollingPaused(true);
        window.clearInterval(timer);
      }
    }, POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [canViewScan, loadScan, scan?.status]);

  const handleCancel = async () => {
    if (
      !scan ||
      !CANCELLABLE_STATUSES.includes(scan.status) ||
      scan.cancellationRequested ||
      cancelling
    ) return;
    setCancelling(true);
    setActionError('');
    try {
      const result = await scanApi.cancelScan(scan.id);
      setScan(dataOf(result));
      await loadScan({ quiet: true });
    } catch (requestError) {
      setActionError(requestError.message || 'The scan could not be cancelled.');
    } finally {
      setCancelling(false);
    }
  };

  const handleExport = async (format) => {
    if (exportingFormat) return;
    setExportingFormat(format);
    setExportError('');
    try {
      const { blob, filename } = await scanApi.exportReport(scanId, format);
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      window.URL.revokeObjectURL(url);
    } catch (requestError) {
      setExportError(requestError.message || `Failed to export report as ${format.toUpperCase()}.`);
    } finally {
      setExportingFormat(null);
    }
  };

  const findingTypes = [...new Set(findings.map((finding) => finding.checkType).filter(Boolean))];
  const findingSeverities = [...new Set(findings.map((finding) => finding.severity).filter(Boolean))];
  const visibleFindings = findings.filter((finding) => (
    (!severityFilter || finding.severity === severityFilter) &&
    (!typeFilter || finding.checkType === typeFilter)
  ));

  if (!profileReady) {
    return (
      <section className="page-shell">
        <LoadingSpinner label="Verifying account and organization approval…" />
      </section>
    );
  }

  if (!canViewScan) {
    return (
      <section className="page-shell">
        {profileError
          ? <div className="message-card error" role="alert">{profileError}</div>
          : (
            <div className="message-card error" role="alert">
              Scan details are available only to an active Security Analyst with an approved organization membership.
            </div>
          )}
        <Link to="/analyst/workspace">Return to analyst workspace</Link>
      </section>
    );
  }

  return (
    <section className="page-shell">
      <div className="page-header">
        <div>
          <p className="eyebrow">Scan job</p>
          <h1>Scan details</h1>
        </div>
        <Link className="secondary-button" to={hasRole(user, 'ADMIN') ? '/admin/scans' : '/analyst/workspace'}>
          {hasRole(user, 'ADMIN') ? 'Back to scan approvals' : 'Back to workspace'}
        </Link>
      </div>

      {error ? (
        <div className="message-card error" role="alert">
          <p>{error}</p>
          <button type="button" className="secondary-button" onClick={() => loadScan()}>Retry scan details</button>
        </div>
      ) : null}
      {actionError ? <div className="message-card error" role="alert">{actionError}</div> : null}
      {pollingPaused ? (
        <div className="message-card" role="status">
          Automatic status refresh paused after five minutes. Refresh scan details to check the backend status again.
        </div>
      ) : null}
      {loading ? <LoadingSpinner label="Loading scan details…" /> : null}
      {!loading && !error && scan ? (
        <>
          <article className="data-card">
            <div className="data-card-header">
              <div>
                <p className="eyebrow">{scan.scanType || 'Scan type unavailable'}</p>
                <h2>{scan.targetName || `Target ${scan.targetId ?? 'unavailable'}`}</h2>
              </div>
              <span className="status-chip" data-status={scan.status}>{statusText(scan.status)}</span>
            </div>
            <dl className="meta-list">
              {scan.targetUrl || scan.url ? <div><dt>Target URL</dt><dd>{scan.targetUrl || scan.url}</dd></div> : null}
              <div><dt>Target ID</dt><dd>{scan.targetId ?? 'Not provided'}</dd></div>
              <div><dt>Scan engine</dt><dd>{scan.scanType === 'PASSIVE_HEADERS' ? 'Native Header Engine' : (scan.scanType || 'Not provided')}</dd></div>
              <div><dt>Progress</dt><dd>{Number.isFinite(scan.progress) ? `${scan.progress}%` : 'Not provided'}</dd></div>
              <div><dt>Created</dt><dd>{dateText(scan.createdAt)}</dd></div>
              <div><dt>Started</dt><dd>{dateText(scan.startedAt)}</dd></div>
              <div><dt>Completed</dt><dd>{dateText(scan.completedAt)}</dd></div>
              {scan.statusMessage ? <div><dt>Status details</dt><dd>{scan.statusMessage}</dd></div> : null}
              {scan.failureReason ? <div><dt>Failure details</dt><dd>{scan.failureReason}</dd></div> : null}
              {scan.reviewedAt ? <div><dt>Decision time</dt><dd>{dateText(scan.reviewedAt)}</dd></div> : null}
              {scan.reviewedByUserId ? <div><dt>Reviewed by</dt><dd>Organization Admin #{scan.reviewedByUserId}</dd></div> : null}
              {scan.rejectionReason ? <div><dt>Rejection reason</dt><dd>{scan.rejectionReason}</dd></div> : null}
            </dl>
            {CANCELLABLE_STATUSES.includes(scan.status) && !scan.cancellationRequested ? (
              <button type="button" className="danger-button" disabled={cancelling} onClick={handleCancel}>
                {cancelling ? 'Cancelling…' : 'Cancel scan'}
              </button>
            ) : null}
          </article>

          <section aria-labelledby="scan-report-heading">
            <div className="page-header">
              <div>
                <p className="eyebrow">Backend report</p>
                <h2 id="scan-report-heading">Report & Exports</h2>
              </div>
              <div className="inline-actions" role="group" aria-label="Export report actions">
                <button
                  type="button"
                  className="secondary-button"
                  disabled={exportingFormat != null}
                  onClick={() => handleExport('json')}
                >
                  {exportingFormat === 'json' ? 'Exporting JSON…' : 'Export JSON'}
                </button>
                <button
                  type="button"
                  className="secondary-button"
                  disabled={exportingFormat != null}
                  onClick={() => handleExport('csv')}
                >
                  {exportingFormat === 'csv' ? 'Exporting CSV…' : 'Export CSV'}
                </button>
                <button
                  type="button"
                  className="secondary-button"
                  disabled={exportingFormat != null}
                  onClick={() => handleExport('pdf')}
                >
                  {exportingFormat === 'pdf' ? 'Exporting PDF…' : 'Export PDF'}
                </button>
              </div>
            </div>

            {exportError ? (
              <div className="message-card error" role="alert">
                {exportError}
              </div>
            ) : null}

            {reportLoading ? (
              <LoadingSpinner label="Loading scan report…" />
            ) : reportError ? (
              <div className="message-card error" role="alert">
                <p>{reportError}</p>
                <button type="button" className="secondary-button" onClick={() => loadScan()}>Retry report</button>
              </div>
            ) : !report ? (
              <div className="empty-state">Report data is unavailable.</div>
            ) : (
              <article className="data-card">
                <div className="data-card-header">
                  <div>
                    <p className="eyebrow">Summary for {report.targetName || `Target ${report.targetId}`}</p>
                    <h3>Organization: {report.organizationName || `Org #${report.organizationId}`}</h3>
                  </div>
                  <span className="status-chip" data-status={report.status}>{statusText(report.status)}</span>
                </div>
                <dl className="meta-list">
                  {report.targetUrl ? <div><dt>Target URL</dt><dd>{report.targetUrl}</dd></div> : null}
                  <div><dt>Total findings</dt><dd>{report.totalFindings ?? 0}</dd></div>
                  <div><dt>High severity</dt><dd>{report.severitySummary?.high ?? 0}</dd></div>
                  <div><dt>Medium severity</dt><dd>{report.severitySummary?.medium ?? 0}</dd></div>
                  <div><dt>Low severity</dt><dd>{report.severitySummary?.low ?? 0}</dd></div>
                  <div><dt>Crawl pages</dt><dd>{report.totalCrawlPages ?? 0}</dd></div>
                </dl>
              </article>
            )}
          </section>

          <section aria-labelledby="scan-findings-heading">
            <div className="page-header">
              <div>
                <p className="eyebrow">Persisted scan output</p>
                <h2 id="scan-findings-heading">Findings</h2>
              </div>
            </div>
            {scan.status !== 'COMPLETED' ? (
              <div className="empty-state">Findings are available after the backend confirms scan completion.</div>
            ) : findingsLoading ? (
              <LoadingSpinner label="Loading findings…" />
            ) : findingsError ? (
              <div className="message-card error" role="alert">
                <p>{findingsError}</p>
                <button type="button" className="secondary-button" onClick={() => loadScan()}>Retry findings</button>
              </div>
            ) : findings.length === 0 ? (
              <div className="empty-state">The backend returned no findings for this completed scan.</div>
            ) : (
              <>
                <div className="finding-filters" aria-label="Finding filters">
                  <label htmlFor="finding-severity-filter">Severity
                    <select id="finding-severity-filter" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                      <option value="">All severities</option>
                      {findingSeverities.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
                    </select>
                  </label>
                  <label htmlFor="finding-type-filter">Finding type
                    <select id="finding-type-filter" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
                      <option value="">All finding types</option>
                      {findingTypes.map((type) => <option key={type} value={type}>{type}</option>)}
                    </select>
                  </label>
                </div>
                {visibleFindings.length === 0 ? (
                  <div className="empty-state">No findings match the selected filters.</div>
                ) : (
                  <div className="card-grid">
                  {visibleFindings.map((finding) => {
                    const isNvdCve = finding.detectionSource === 'NVD_CVE_LOOKUP' || finding.checkType === 'KNOWN_VULNERABILITY_CVE';
                    const cveDetails = parseCveEvidence(finding.evidence);

                    return (
                      <article className="data-card" key={finding.id}>
                        <div className="data-card-header">
                          <div>
                            <p className="eyebrow">
                              {isNvdCve ? 'Known vulnerability / NVD lookup' : (finding.checkType || 'Check type unavailable')}
                            </p>
                            <h3>{statusText(finding.verificationStatus || 'Finding')}</h3>
                          </div>
                          <span className="status-chip" data-status={finding.severity}>{finding.severity || 'Severity unavailable'}</span>
                        </div>
                        <dl className="meta-list">
                          {cveDetails?.cveId ? (
                            <div>
                              <dt>CVE Identifier</dt>
                              <dd><strong>{cveDetails.cveId}</strong> (Potential match from software version)</dd>
                            </div>
                          ) : null}
                          {cveDetails?.cvssScore ? (
                            <div>
                              <dt>NVD CVSS details</dt>
                              <dd>
                                Score: {cveDetails.cvssScore}
                                {cveDetails.cvssSeverity ? ` (${cveDetails.cvssSeverity})` : ''}
                                {cveDetails.cvssVector ? ` — Vector: ${cveDetails.cvssVector}` : ''}
                                <span className="muted" style={{ display: 'block', fontSize: '0.85rem' }}>
                                  * NVD-sourced metric; local scanner severity is {finding.severity || 'LOW'}.
                                </span>
                              </dd>
                            </div>
                          ) : null}
                          <div><dt>Affected component</dt><dd>{finding.affectedComponent || 'Not provided'}</dd></div>
                          <div><dt>Evidence</dt><dd>{finding.evidence || 'Not provided'}</dd></div>
                          <div><dt>Explanation</dt><dd>{finding.rationale || 'Not provided'}</dd></div>
                          <div><dt>Detection source</dt><dd>{detectionSourceLabel(finding.detectionSource)}</dd></div>
                          <div><dt>Remediation</dt><dd>{finding.remediation || 'Not provided'}</dd></div>
                          <div><dt>Detected</dt><dd>{dateText(finding.detectedAt)}</dd></div>
                        </dl>
                      </article>
                    );
                  })}
                  </div>
                )}
              </>
            )}
          </section>

          <section aria-labelledby="scan-crawl-pages-heading">
            <div className="page-header">
              <div>
                <p className="eyebrow">Persisted crawl output</p>
                <h2 id="scan-crawl-pages-heading">Crawl pages</h2>
              </div>
            </div>
            {crawlPagesLoading ? (
              <LoadingSpinner label="Loading crawl pages…" />
            ) : crawlPagesError ? (
              <div className="message-card error" role="alert">
                <p>{crawlPagesError}</p>
                <button type="button" className="secondary-button" onClick={() => loadScan()}>Retry crawl pages</button>
              </div>
            ) : crawlPages.length === 0 ? (
              <div className="empty-state">No crawl pages have been returned for this scan.</div>
            ) : (
              <div className="data-table-wrapper">
                <table className="data-table">
                  <caption className="sr-only">Crawl pages discovered by this scan</caption>
                  <thead>
                    <tr>
                      <th scope="col">URL</th>
                      <th scope="col">Depth</th>
                      <th scope="col">HTTP status</th>
                      <th scope="col">Response bytes</th>
                      <th scope="col">Discovered links</th>
                      <th scope="col">Discovered</th>
                    </tr>
                  </thead>
                  <tbody>
                    {crawlPages.map((page) => (
                      <tr key={page.id || `${page.url}-${page.depth}`}>
                        <td>{page.url || 'Not provided'}</td>
                        <td>{Number.isFinite(page.depth) ? page.depth : 'Not provided'}</td>
                        <td>{Number.isFinite(page.statusCode) ? page.statusCode : 'Not provided'}</td>
                        <td>{Number.isFinite(page.responseBytes) ? page.responseBytes : 'Not provided'}</td>
                        <td>{Number.isFinite(page.discoveredLinks) ? page.discoveredLinks : 'Not provided'}</td>
                        <td>{dateText(page.discoveredAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      ) : null}
    </section>
  );
}
