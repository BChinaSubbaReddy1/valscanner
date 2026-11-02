function DistributionChart({ title, items, emptyText }) {
  const maximum = Math.max(1, ...(items || []).map((item) => item.count || 0));
  return (
    <article className="scan-analytics-card">
      <h3>{title}</h3>
      {items?.length ? (
        <ul className="scan-analytics-bars">
          {items.map((item) => (
            <li key={item.key}>
              <div className="scan-analytics-bar-label">
                <span>{item.label}</span>
                <strong>{item.count}</strong>
              </div>
              <progress max={maximum} value={item.count} aria-label={`${item.label}: ${item.count}`} />
            </li>
          ))}
        </ul>
      ) : <p className="muted">{emptyText}</p>}
    </article>
  );
}

function EndpointChart({ endpoints, selectedEndpoint, onSelect }) {
  const maximum = Math.max(1, ...endpoints.map((endpoint) => endpoint.findingCount || 0));
  const severitySegments = [
    { key: 'CRITICAL', color: '#7f1d1d', label: 'Critical' },
    { key: 'HIGH', color: '#b42318', label: 'High' },
    { key: 'MEDIUM', color: '#b54708', label: 'Medium' },
    { key: 'LOW', color: '#2563a6', label: 'Low' },
  ];
  return (
    <article className="scan-analytics-card scan-endpoint-card">
      <h3>Findings by discovered endpoint</h3>
      <p className="muted">Counts combine persisted findings with same-origin crawl-page records.</p>
      {endpoints.length ? (
        <ul className="scan-endpoint-bars">
          {endpoints.slice(0, 20).map((endpoint, index) => {
            const key = endpoint.url || `unavailable-${index}`;
            const selected = selectedEndpoint === (endpoint.url || '__endpoint_unavailable__');
            return (
              <li key={key}>
                <button
                  type="button"
                  className={selected ? 'scan-endpoint-row selected' : 'scan-endpoint-row'}
                  aria-pressed={selected}
                  aria-label={`${endpoint.url || 'Endpoint unavailable'}: ${endpoint.findingCount} findings`}
                  title={endpoint.url || 'Endpoint unavailable'}
                  onClick={() => onSelect(selected ? '' : (endpoint.url || '__endpoint_unavailable__'))}
                >
                  <span className="scan-endpoint-label">
                    {endpoint.url || 'Endpoint unavailable'}
                    <small>{endpoint.crawled ? `Crawled${endpoint.httpStatusCode ? ` · HTTP ${endpoint.httpStatusCode}` : ''}` : 'Finding location only'}</small>
                  </span>
                  <span className="scan-endpoint-meter" aria-hidden="true">
                    {severitySegments.map((segment) => {
                      const count = endpoint.severities?.[segment.key] || 0;
                      return count > 0 ? (
                        <span
                          key={segment.key}
                          title={`${segment.label}: ${count}`}
                          style={{ width: `${(count / maximum) * 100}%`, backgroundColor: segment.color }}
                        />
                      ) : null;
                    })}
                    {Math.max(0, endpoint.findingCount - severitySegments.reduce(
                      (sum, segment) => sum + (endpoint.severities?.[segment.key] || 0), 0,
                    )) > 0 ? (
                      <span
                        title="Other severity"
                        style={{
                          width: `${(Math.max(0, endpoint.findingCount - severitySegments.reduce(
                            (sum, segment) => sum + (endpoint.severities?.[segment.key] || 0), 0,
                          )) / maximum) * 100}%`,
                          backgroundColor: '#667085',
                        }}
                      />
                    ) : null}
                  </span>
                  <strong>{endpoint.findingCount}</strong>
                </button>
              </li>
            );
          })}
        </ul>
      ) : <p className="muted">No endpoint or crawl-page records were persisted.</p>}
      {endpoints.length > 20 ? <p className="muted">Showing the 20 endpoints with the most findings; the API reports {endpoints.length} of the bounded endpoint set.</p> : null}
      <ul className="chart-legend">
        {severitySegments.map((segment) => (
          <li key={segment.key}><span style={{ backgroundColor: segment.color }} aria-hidden="true" />{segment.label}</li>
        ))}
      </ul>
      {selectedEndpoint ? (
        <button type="button" className="text-button" onClick={() => onSelect('')}>Clear endpoint selection</button>
      ) : null}
    </article>
  );
}

function displayStatus(value) {
  return String(value || 'Unavailable').replace(/_/g, ' ');
}

export default function ScanAnalyticsPanel({
  analytics,
  scans = [],
  targetFilter,
  onTargetChange,
  onScanChange,
  scanListLoading,
  scanListError,
  loading,
  error,
  onRetry,
  selectedEndpoint,
  onSelectEndpoint,
}) {
  if (loading) {
    return <p className="muted" role="status">Loading persisted scan analytics…</p>;
  }
  if (error) {
    return (
      <div className="message-card error" role="alert">
        <p>{error}</p>
        <button type="button" className="secondary-button" onClick={onRetry}>Retry scan analytics</button>
      </div>
    );
  }
  if (!analytics) {
    return <div className="empty-state">Scan analytics are not available for this scan yet.</div>;
  }

  const history = analytics.history || {};
  const coverage = analytics.ruleCoverage || {};
  const targetOptions = [...new Map(scans.map((item) => [String(item.targetId), item.targetName || `Target #${item.targetId}`])).entries()];
  const filteredScans = scans.filter((item) => String(item.targetId) === String(targetFilter));
  return (
    <section className="scan-analytics" aria-labelledby="scan-analytics-heading">
      <div className="page-header">
        <div>
          <p className="eyebrow">Persisted scan evidence</p>
          <h2 id="scan-analytics-heading">Link-wise finding analytics</h2>
        </div>
        <div className="scan-analytics-filters" aria-label="Target and scan filters">
          <label htmlFor="analytics-target-filter">Target
            <select id="analytics-target-filter" value={targetFilter} onChange={(event) => onTargetChange(event.target.value)}>
              {targetOptions.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
            </select>
          </label>
          <label htmlFor="analytics-scan-filter">Scan
            <select
              id="analytics-scan-filter"
              value={String(analytics.scanId)}
              onChange={(event) => onScanChange(event.target.value)}
              disabled={scanListLoading || filteredScans.length === 0}
            >
              {filteredScans.map((item) => (
                <option key={item.id} value={String(item.id)}>
                  #{item.id} · {displayStatus(item.scanType)} · {displayStatus(item.status)}
                </option>
              ))}
            </select>
          </label>
        </div>
        {scanListError ? <div className="message-card error" role="alert">{scanListError}</div> : null}
        <p className="muted">
          Target #{analytics.targetId} · Scan #{analytics.scanId} · {analytics.totalFindings} findings · {analytics.totalCrawlPages} crawl pages
        </p>
      </div>
      {analytics.resultCompleteness !== 'FULL' ? (
        <div className="message-card" role="status">
          Results are {displayStatus(analytics.resultCompleteness).toLowerCase()}. Missing engine output is not treated as a clean scan.
        </div>
      ) : null}
      {analytics.duplicateEngineObservationsSuppressed > 0 ? (
        <p className="muted">
          Showing {analytics.totalFindings} exact finding identities after suppressing {analytics.duplicateEngineObservationsSuppressed} duplicate cross-engine observation(s) from {analytics.rawFindingObservations} source observations. Engine attribution remains available below.
        </p>
      ) : null}
      {analytics.endpointsTruncated ? (
        <div className="message-card" role="status">Endpoint analytics are bounded to the 100 highest-count locations.</div>
      ) : null}

      <div className="scan-analytics-grid">
        <EndpointChart
          endpoints={analytics.endpoints || []}
          selectedEndpoint={selectedEndpoint}
          onSelect={onSelectEndpoint}
        />
        <DistributionChart title="Findings by severity" items={analytics.severities} emptyText="No persisted findings." />
        <DistributionChart title="Finding types" items={analytics.findingTypes} emptyText="No finding types were reported." />
        <DistributionChart title="OWASP Top 10 categories" items={analytics.owaspCategories} emptyText="No findings map to the explicitly supported categories." />
        <DistributionChart title="Detection-source observations (duplicates retained for attribution)" items={analytics.detectionSources} emptyText="No detection-source evidence was persisted." />
        <DistributionChart title="Generated finding rules" items={analytics.findingRules} emptyText="No finding rules were reported." />
      </div>
      <p className="muted">
        {analytics.unmappedOwaspFindings || 0} findings are not mapped to the supported OWASP categories; no category is inferred for them.
      </p>

      <article className="scan-analytics-card scan-coverage-card">
        <h3>Rule and source coverage</h3>
        <dl className="meta-list">
          <div><dt>ZAP rule inventory snapshot</dt><dd>{displayStatus(coverage.inventoryStatus)}</dd></div>
          <div><dt>Scan mode</dt><dd>{displayStatus(analytics.scanType)}</dd></div>
          <div><dt>Native engine</dt><dd>{displayStatus(analytics.nativeEngineStatus)}</dd></div>
          <div><dt>ZAP engine</dt><dd>{displayStatus(analytics.zapEngineStatus)}</dd></div>
          <div><dt>Active scan requested</dt><dd>{coverage.activeScanRequested ? 'Yes' : 'No'}</dd></div>
          <div><dt>Rule execution evidence</dt><dd>{coverage.executionEvidence || 'Unavailable'}</dd></div>
          <div><dt>Enabled rules that generated Native findings</dt><dd>{coverage.nativeRulesWithFindings?.join('; ') || 'No Native finding rule IDs reported.'}</dd></div>
          <div><dt>Enabled rules that generated ZAP findings</dt><dd>{coverage.zapRulesWithFindings?.join('; ') || 'No ZAP finding rule IDs reported.'}</dd></div>
          <div><dt>Unsupported or skipped checks</dt><dd>{coverage.unsupportedOrSkippedChecks?.join('; ') || 'None reported.'}</dd></div>
        </dl>
        {coverage.passiveEnabledRules?.length ? (
          <details>
            <summary>{coverage.passiveEnabledRules.length} passive rules enabled in the scan-time snapshot</summary>
            <ul>{coverage.passiveEnabledRules.map((rule) => <li key={rule}>{rule}</li>)}</ul>
          </details>
        ) : null}
        {coverage.activeEnabledRules?.length ? (
          <details>
            <summary>{coverage.activeEnabledRules.length} active rules enabled in the scan-time snapshot</summary>
            <ul>{coverage.activeEnabledRules.map((rule) => <li key={rule}>{rule}</li>)}</ul>
          </details>
        ) : null}
      </article>

      <article className="scan-analytics-card scan-history-card">
        <h3>Comparable scan history</h3>
        <p className="muted">{history.explanation || 'History comparison is unavailable.'}</p>
        {history.previousScanId ? <p>Compared with scan #{history.previousScanId}.</p> : null}
        {history.comparable ? (
          <dl className="scan-history-counts">
            <div><dt>New</dt><dd>{history.newFindings}</dd></div>
            <div><dt>Resolved</dt><dd>{history.resolvedFindings}</dd></div>
            <div><dt>Persistent</dt><dd>{history.persistentFindings}</dd></div>
            <div><dt>Severity changed</dt><dd>{history.severityChangedFindings}</dd></div>
          </dl>
        ) : <p className="muted">Counts are withheld until a full comparable scan is available.</p>}
      </article>
    </section>
  );
}
