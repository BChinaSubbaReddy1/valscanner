import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { scanApi } from '../../api/client';
import { useAuth } from '../../auth/useAuth';
import LoadingSpinner from '../../components/LoadingSpinner';
import ScanAnalyticsPanel from '../../components/ScanAnalyticsPanel';
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

function findingOwaspCategory(finding) {
  const type = String(finding?.checkType || '').toUpperCase();
  const cwe = String(finding?.sourceCweId || '').toUpperCase();
  if (type.includes('SQL_INJECTION') || type.includes('XSS') || cwe === 'CWE-89' || cwe === 'CWE-79') {
    return 'A03:2021 Injection';
  }
  if (type.startsWith('MISSING_') || type.startsWith('COOKIE_') || type.startsWith('INFORMATION_DISCLOSURE_')
    || ['CWE-16', 'CWE-1004', 'CWE-614', 'CWE-693'].includes(cwe)) {
    return 'A05:2021 Security Misconfiguration';
  }
  return 'Unmapped';
}

function normalizedEndpoint(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return `${url.protocol.toLowerCase()}//${url.host.toLowerCase()}${url.pathname}${url.search}`;
  } catch {
    return null;
  }
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
  const cveMatch = evidence.match(/\b(CVE-\d{4}-\d{4,7})\b/i);
  if (!cveMatch) return null;
  const cveId = cveMatch[1].toUpperCase();

  const backendCvssMatch = evidence.match(/NVD CVSS:\s*(\d{1,2}(?:\.\d+)?)\s*\(([A-Za-z]+);\s*([^)]+)\)/i);
  const legacyScoreMatch = evidence.match(/CVSS score:\s*(\d{1,2}(?:\.\d+)?)/i);
  const scoreValue = backendCvssMatch?.[1] || legacyScoreMatch?.[1] || null;
  const scoreNumber = scoreValue === null ? Number.NaN : Number(scoreValue);
  const cvssScore = Number.isFinite(scoreNumber) && scoreNumber >= 0 && scoreNumber <= 10
    ? scoreValue
    : null;

  const legacySeverityMatch = evidence.match(/severity:\s*([A-Za-z]+)/i);
  const severityValue = backendCvssMatch?.[2] || legacySeverityMatch?.[1] || null;
  const cvssSeverity = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severityValue?.toUpperCase())
    ? severityValue.toUpperCase()
    : null;

  const legacyVectorMatch = evidence.match(/vector:\s*([^)]+)\)/i);
  const vectorValue = backendCvssMatch?.[3]?.trim() || legacyVectorMatch?.[1]?.trim() || null;
  const cvssVector = vectorValue && /^CVSS:3\.[01]\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[HLN]\/I:[HLN]\/A:[HLN]$/i.test(vectorValue)
    ? vectorValue
    : null;

  return {
    cveId,
    cvssScore,
    cvssSeverity,
    cvssVector,
  };
}

export default function ScanDetailsPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const { user, refreshUser } = useAuth();
  const [profileReady, setProfileReady] = useState(false);
  const [profileError, setProfileError] = useState('');
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [crawlPages, setCrawlPages] = useState([]);
  const [report, setReport] = useState(null);
  const [scanAnalytics, setScanAnalytics] = useState(null);
  const [accessibleScans, setAccessibleScans] = useState([]);
  const [scanListLoading, setScanListLoading] = useState(true);
  const [scanListError, setScanListError] = useState('');
  const [analyticsTargetFilter, setAnalyticsTargetFilter] = useState('');
  const [correlations, setCorrelations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [crawlPagesLoading, setCrawlPagesLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [scanAnalyticsLoading, setScanAnalyticsLoading] = useState(false);
  const [correlationsLoading, setCorrelationsLoading] = useState(false);
  const [error, setError] = useState('');
  const [findingsError, setFindingsError] = useState('');
  const [crawlPagesError, setCrawlPagesError] = useState('');
  const [reportError, setReportError] = useState('');
  const [scanAnalyticsError, setScanAnalyticsError] = useState('');
  const [correlationsError, setCorrelationsError] = useState('');
  const [exportError, setExportError] = useState('');
  const [exportingFormat, setExportingFormat] = useState(null);
  const [actionError, setActionError] = useState('');
  const [cancelling, setCancelling] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [engineFilter, setEngineFilter] = useState('');
  const [endpointFilter, setEndpointFilter] = useState('');
  const [pollingPaused, setPollingPaused] = useState(false);
  const pollingAttempts = useRef(0);
  const scanLoadLock = useRef(false);
  const canViewScan = profileReady && canViewScanForUser(user);

  useEffect(() => {
    if (!canViewScan) return undefined;
    let active = true;
    scanApi.listScans({ page: 0, size: 100 })
      .then((response) => {
        const page = dataOf(response);
        const content = Array.isArray(page) ? page : page?.content;
        if (!Array.isArray(content)) {
          throw new Error('The scan list response was invalid.');
        }
        if (active) {
          setAccessibleScans(content);
          setScanListError('');
        }
      })
      .catch((requestError) => {
        if (active) {
          setScanListError(requestError.message || 'Unable to load authorized scan filters.');
        }
      })
      .finally(() => {
        if (active) setScanListLoading(false);
      });
    return () => {
      active = false;
    };
  }, [canViewScan]);

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
      if (job?.targetId != null) setAnalyticsTargetFilter(String(job.targetId));
      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(job?.status)) {
        setScanAnalyticsLoading(true);
        try {
          const analyticsResult = await scanApi.getScanAnalytics(scanId);
          setScanAnalytics(dataOf(analyticsResult) || null);
          setScanAnalyticsError('');
        } catch (requestError) {
          setScanAnalytics(null);
          setScanAnalyticsError(requestError.message || 'Unable to load persisted scan analytics.');
        } finally {
          setScanAnalyticsLoading(false);
        }
      } else {
        setScanAnalytics(null);
        setScanAnalyticsError('');
      }
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
        setScanAnalytics(null);
        setScanAnalyticsError('');
        setScanAnalyticsLoading(false);
        setReportError(requestError.message || 'Unable to load scan report.');
      } finally {
        setReportLoading(false);
      }

      setCorrelationsLoading(true);
      try {
        const correlationResult = await scanApi.listFindingCorrelations(scanId);
        const data = dataOf(correlationResult);
        setCorrelations(Array.isArray(data) ? data : []);
        setCorrelationsError('');
      } catch (requestError) {
        setCorrelations([]);
        setCorrelationsError(requestError.message || 'Unable to load cross-engine finding overlaps.');
      } finally {
        setCorrelationsLoading(false);
      }
    } catch (requestError) {
      setScan(null);
      setFindings([]);
      setCrawlPages([]);
      setReport(null);
      setCorrelations([]);
      setCorrelationsError('');
      setCorrelationsLoading(false);
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
  const findingCategories = [...new Set(findings.map(findingOwaspCategory))];
  const findingEngines = [...new Set(findings.map((finding) => finding.detectionSource).filter(Boolean))];
  const findingEndpoints = [...new Set(findings
    .map((finding) => finding.endpointUrl || finding.affectedComponent)
    .map(normalizedEndpoint)
    .filter(Boolean))];
  const visibleFindings = findings.filter((finding) => (
    (!severityFilter || finding.severity === severityFilter) &&
    (!typeFilter || finding.checkType === typeFilter) &&
    (!categoryFilter || findingOwaspCategory(finding) === categoryFilter) &&
    (!engineFilter || finding.detectionSource === engineFilter) &&
    (!endpointFilter || (endpointFilter === '__endpoint_unavailable__'
      ? !normalizedEndpoint(finding.endpointUrl || finding.affectedComponent)
      : normalizedEndpoint(finding.endpointUrl || finding.affectedComponent) === endpointFilter))
  ));
  const analyticsScans = scan
    ? [...new Map([...accessibleScans, scan].map((item) => [String(item.id), item])).values()]
    : accessibleScans;
  const changeAnalyticsTarget = (targetId) => {
    setAnalyticsTargetFilter(targetId);
    const nextScan = analyticsScans.find((item) => String(item.targetId) === String(targetId));
    if (nextScan && String(nextScan.id) !== String(scanId)) {
      const base = hasRole(user, 'ADMIN') ? '/admin/scans' : '/analyst/scans';
      navigate(`${base}/${nextScan.id}`);
    }
  };
  const changeAnalyticsScan = (nextScanId) => {
    if (!nextScanId || String(nextScanId) === String(scanId)) return;
    const base = hasRole(user, 'ADMIN') ? '/admin/scans' : '/analyst/scans';
    navigate(`${base}/${nextScanId}`);
  };

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
              <span className="status-chip" data-status={scan.status}>
                {statusText(scan.status)}
                {scan.executionSummary?.resultCompleteness === 'PARTIAL' ? ' · PARTIAL RESULTS' : ''}
              </span>
            </div>
            <dl className="meta-list">
              {scan.targetUrl || scan.url ? <div><dt>Target URL</dt><dd>{scan.targetUrl || scan.url}</dd></div> : null}
              <div><dt>Target ID</dt><dd>{scan.targetId ?? 'Not provided'}</dd></div>
              <div><dt>Scan mode</dt><dd>{scan.scanType || 'Not provided'}</dd></div>
              <div><dt>Native engine</dt><dd>{scan.executionSummary?.nativeEngineStatus || 'Status unavailable'}</dd></div>
              <div><dt>OWASP ZAP requested</dt><dd>{typeof scan.executionSummary?.zapRequested === 'boolean' ? (scan.executionSummary.zapRequested ? 'Yes' : 'No') : 'Not reported'}</dd></div>
              <div><dt>OWASP ZAP</dt><dd>{scan.executionSummary?.zapEngineStatus || 'Status unavailable'}</dd></div>
              {scan.executionSummary?.zapFailureReason ? (
                <div><dt>OWASP ZAP failure or skip reason</dt><dd>{scan.executionSummary.zapFailureReason}</dd></div>
              ) : null}
              <div><dt>ZAP spider</dt><dd>{scan.executionSummary?.zapSpiderStatus || 'Not reported'}</dd></div>
              <div><dt>ZAP spider URLs discovered</dt><dd>{scan.executionSummary?.zapSpiderDiscoveredCount ?? 'Not reported'}</dd></div>
              <div><dt>ZAP passive analysis</dt><dd>{scan.executionSummary?.zapPassiveStatus || 'Not reported'}</dd></div>
              <div><dt>ZAP alert count</dt><dd>{scan.executionSummary?.zapAlertCount ?? 'Not reported'}</dd></div>
              {scan.executionSummary?.zapActiveStatus ? (
                <div><dt>ZAP active scan</dt><dd>{scan.executionSummary.zapActiveStatus}</dd></div>
              ) : null}
              <div><dt>Discovered same-origin pages</dt><dd>{scan.executionSummary?.discoveredPageCount ?? 'Not reported'}</dd></div>
              <div><dt>Visited pages</dt><dd>{scan.executionSummary?.visitedPageCount ?? 'Not reported'}</dd></div>
              <div><dt>Passively tested pages</dt><dd>{scan.executionSummary?.testedPassivePageCount ?? 'Not reported'}</dd></div>
              {scan.executionSummary?.checksInScope?.length ? (
                <div><dt>Checks in scope</dt><dd>{scan.executionSummary.checksInScope.join('; ')}</dd></div>
              ) : null}
              {scan.executionSummary?.checksOutOfScope?.length ? (
                <div><dt>Checks out of scope</dt><dd>{scan.executionSummary.checksOutOfScope.join('; ')}</dd></div>
              ) : null}
              {scan.executionSummary?.adaptiveCheckSelections?.length ? (
                <div><dt>Adaptive check selections</dt><dd>{scan.executionSummary.adaptiveCheckSelections.join(' | ')}</dd></div>
              ) : null}
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

          <ScanAnalyticsPanel
            analytics={scanAnalytics}
            scans={analyticsScans}
            targetFilter={analyticsTargetFilter}
            onTargetChange={changeAnalyticsTarget}
            onScanChange={changeAnalyticsScan}
            scanListLoading={canViewScan && scanListLoading}
            scanListError={scanListError}
            loading={scanAnalyticsLoading}
            error={scanAnalyticsError}
            onRetry={() => loadScan()}
            selectedEndpoint={endpointFilter}
            onSelectEndpoint={setEndpointFilter}
          />

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
                  <div><dt>Discovered same-origin pages</dt><dd>{report.executionSummary?.discoveredPageCount ?? 'Not reported'}</dd></div>
                  <div><dt>Visited pages</dt><dd>{report.executionSummary?.visitedPageCount ?? 'Not reported'}</dd></div>
                  <div><dt>Passively tested pages</dt><dd>{report.executionSummary?.testedPassivePageCount ?? 'Not reported'}</dd></div>
                  <div><dt>Persisted HTML crawl records</dt><dd>{report.totalCrawlPages ?? 0}</dd></div>
                  <div><dt>Native engine status</dt><dd>{report.executionSummary?.nativeEngineStatus || 'Status unavailable'}</dd></div>
                  <div><dt>OWASP ZAP requested</dt><dd>{typeof report.executionSummary?.zapRequested === 'boolean' ? (report.executionSummary.zapRequested ? 'Yes' : 'No') : 'Not reported'}</dd></div>
                  <div><dt>OWASP ZAP status</dt><dd>{report.executionSummary?.zapEngineStatus || 'Status unavailable'}</dd></div>
                  {report.executionSummary?.zapFailureReason ? (
                    <div><dt>OWASP ZAP failure or skip reason</dt><dd>{report.executionSummary.zapFailureReason}</dd></div>
                  ) : null}
                  <div><dt>ZAP spider</dt><dd>{report.executionSummary?.zapSpiderStatus || 'Not reported'}</dd></div>
                  <div><dt>ZAP spider URLs discovered</dt><dd>{report.executionSummary?.zapSpiderDiscoveredCount ?? 'Not reported'}</dd></div>
                  <div><dt>ZAP passive analysis</dt><dd>{report.executionSummary?.zapPassiveStatus || 'Not reported'}</dd></div>
                  <div><dt>ZAP alert count</dt><dd>{report.executionSummary?.zapAlertCount ?? 'Not reported'}</dd></div>
                  {report.executionSummary?.zapActiveStatus ? (
                    <div><dt>ZAP active scan</dt><dd>{report.executionSummary.zapActiveStatus}</dd></div>
                  ) : null}
                  {report.executionSummary?.checksInScope?.length ? (
                    <div><dt>Checks in scope</dt><dd>{report.executionSummary.checksInScope.join('; ')}</dd></div>
                  ) : null}
                  {report.executionSummary?.checksOutOfScope?.length ? (
                    <div><dt>Checks out of scope</dt><dd>{report.executionSummary.checksOutOfScope.join('; ')}</dd></div>
                  ) : null}
                </dl>
              </article>
            )}
          </section>

          <section aria-labelledby="scan-correlations-heading">
            <div className="page-header">
              <div>
                <p className="eyebrow">Research evaluation signal</p>
                <h2 id="scan-correlations-heading">Finding relationships</h2>
              </div>
            </div>
            <p className="muted">
              Relationships distinguish exact duplicates, same-endpoint findings, and findings with no observed relationship.
              Shared endpoint evidence does not establish a causal attack path or exploitability.
            </p>
            {correlationsLoading ? (
              <LoadingSpinner label="Loading finding relationships…" />
            ) : correlationsError ? (
              <div className="message-card error" role="alert">
                <p>{correlationsError}</p>
                <button type="button" className="secondary-button" onClick={() => loadScan()}>Retry relationships</button>
              </div>
            ) : correlations.length === 0 ? (
              <div className="empty-state">No findings were available for relationship analysis.</div>
            ) : (
              <div className="card-grid">
                {correlations.map((correlation) => (
                  <article className="data-card" key={`${correlation.relationshipType}-${(correlation.findingIds || []).join('-')}`}>
                    <h3>{correlation.checkType}</h3>
                    <dl className="meta-list">
                      <div><dt>Endpoint or component</dt><dd>{correlation.affectedComponent}</dd></div>
                      <div><dt>Detection engines</dt><dd>{(correlation.detectionEngines || []).join(', ')}</dd></div>
                      <div><dt>Finding IDs</dt><dd>{(correlation.findingIds || []).join(', ')}</dd></div>
                      {correlation.relationshipType ? <div><dt>Relationship</dt><dd>{statusText(correlation.relationshipType)}</dd></div> : null}
                      {correlation.matchingEvidence ? <div><dt>Matching evidence</dt><dd>{correlation.matchingEvidence}</dd></div> : null}
                      {correlation.confidence ? <div><dt>Match confidence</dt><dd>{correlation.confidence}</dd></div> : null}
                      <div><dt>Interpretation</dt><dd>{correlation.interpretation}</dd></div>
                    </dl>
                  </article>
                ))}
              </div>
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
                  <label htmlFor="finding-category-filter">OWASP category
                    <select id="finding-category-filter" value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)}>
                      <option value="">All categories</option>
                      {findingCategories.map((category) => <option key={category} value={category}>{category}</option>)}
                    </select>
                  </label>
                  <label htmlFor="finding-engine-filter">Detection engine
                    <select id="finding-engine-filter" value={engineFilter} onChange={(event) => setEngineFilter(event.target.value)}>
                      <option value="">All engines</option>
                      {findingEngines.map((engine) => <option key={engine} value={engine}>{detectionSourceLabel(engine)}</option>)}
                    </select>
                  </label>
                  <label htmlFor="finding-endpoint-filter">Endpoint
                    <select id="finding-endpoint-filter" value={endpointFilter} onChange={(event) => setEndpointFilter(event.target.value)}>
                      <option value="">All endpoints</option>
                      <option value="__endpoint_unavailable__">Endpoint unavailable</option>
                      {findingEndpoints.map((endpoint) => <option key={endpoint} value={endpoint}>{endpoint}</option>)}
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
                            <p className="muted">Automated status does not independently confirm exploitability.</p>
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
                          {Number.isFinite(Number(finding.priorityScore)) && finding.priorityLevel ? (
                            <div>
                              <dt>Technical triage priority</dt>
                              <dd>
                                {finding.priorityLevel} ({finding.priorityScore}/100)
                                <span className="muted" style={{ display: 'block', fontSize: '0.85rem' }}>
                                  {finding.priorityExplanation || 'Derived from available finding evidence; not CVSS or a verified exploitability rating.'}
                                </span>
                              </dd>
                            </div>
                          ) : null}
                          <div><dt>Affected component</dt><dd>{finding.affectedComponent || 'Not provided'}</dd></div>
                          <div><dt>Endpoint</dt><dd>{finding.endpointUrl || 'Not available'}</dd></div>
                          <div><dt>HTTP method</dt><dd>{finding.httpMethod || 'Not available'}</dd></div>
                          <div><dt>Parameter</dt><dd>{finding.parameterName || 'Not applicable or unavailable'}</dd></div>
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
              <p className="muted">
                Discovered pages are unique same-origin URLs found in visited markup; visited pages are successfully fetched responses;
                passively tested pages are responses checked by the native passive engine. Crawl limits mean these counts do not establish
                complete site coverage. Persisted crawl records include HTML pages only.
              </p>
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
