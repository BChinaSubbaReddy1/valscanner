const CHART_WIDTH = 840;
const CHART_HEIGHT = 250;
const PADDING = { top: 20, right: 18, bottom: 34, left: 36 };

function labelDate(value) {
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })
    .format(new Date(`${value}T00:00:00Z`));
}

function LineChart({ points, series, label }) {
  const plotWidth = CHART_WIDTH - PADDING.left - PADDING.right;
  const plotHeight = CHART_HEIGHT - PADDING.top - PADDING.bottom;
  const maxValue = Math.max(1, ...points.flatMap((point) => series.map((item) => point[item.key] || 0)));
  const x = (index) => PADDING.left + (points.length <= 1
    ? plotWidth / 2
    : index * plotWidth / (points.length - 1));
  const y = (value) => PADDING.top + plotHeight - (value / maxValue) * plotHeight;
  const labelIndexes = new Set([0, Math.floor((points.length - 1) / 2), points.length - 1]);

  return (
    <svg className="analytics-chart" viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`} role="img" aria-label={label}>
      <title>{label}</title>
      <desc>Historical daily counts for the selected date range.</desc>
      {[0, 0.5, 1].map((fraction) => {
        const gridY = PADDING.top + plotHeight * fraction;
        return (
          <g key={fraction}>
            <line x1={PADDING.left} x2={CHART_WIDTH - PADDING.right} y1={gridY} y2={gridY} className="chart-grid-line" />
            <text x={PADDING.left - 8} y={gridY + 4} textAnchor="end" className="chart-date-label">
              {Math.round(maxValue * (1 - fraction))}
            </text>
          </g>
        );
      })}
      {series.map((item) => (
        <polyline
          key={item.key}
          points={points.map((point, index) => `${x(index)},${y(point[item.key] || 0)}`).join(' ')}
          fill="none"
          stroke={item.color}
          strokeWidth="3"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      ))}
      {points.map((point, index) => labelIndexes.has(index) ? (
        <text key={point.date} x={x(index)} y={CHART_HEIGHT - 8} textAnchor="middle" className="chart-date-label">
          {labelDate(point.date)}
        </text>
      ) : null)}
    </svg>
  );
}

function SeverityChart({ points, days }) {
  const plotWidth = CHART_WIDTH - PADDING.left - PADDING.right;
  const plotHeight = CHART_HEIGHT - PADDING.top - PADDING.bottom;
  const values = points.map((point) => (point.highFindings || 0)
    + (point.mediumFindings || 0) + (point.lowFindings || 0));
  const maxValue = Math.max(1, ...values);
  const slotWidth = plotWidth / Math.max(points.length, 1);
  const barWidth = Math.max(2, Math.min(14, slotWidth * 0.62));
  const labelIndexes = new Set([0, Math.floor((points.length - 1) / 2), points.length - 1]);
  const keys = [
    { key: 'highFindings', color: '#b42318' },
    { key: 'mediumFindings', color: '#b54708' },
    { key: 'lowFindings', color: '#2563a6' },
  ];

  return (
    <svg
      className="analytics-chart"
      viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`}
      role="img"
      aria-label={`Daily findings by severity over the last ${days} days`}
    >
      <title>Daily findings by severity</title>
      <desc>Stacked daily finding counts from persisted scan findings.</desc>
      {[0, 0.5, 1].map((fraction) => {
        const gridY = PADDING.top + plotHeight * fraction;
        return (
          <g key={fraction}>
            <line x1={PADDING.left} x2={CHART_WIDTH - PADDING.right} y1={gridY} y2={gridY} className="chart-grid-line" />
            <text x={PADDING.left - 8} y={gridY + 4} textAnchor="end" className="chart-date-label">
              {Math.round(maxValue * (1 - fraction))}
            </text>
          </g>
        );
      })}
      {points.map((point, index) => {
        let stackHeight = 0;
        const barX = PADDING.left + index * slotWidth + (slotWidth - barWidth) / 2;
        return (
          <g key={point.date}>
            {keys.map((item) => {
              const value = point[item.key] || 0;
              const height = value / maxValue * plotHeight;
              const bar = (
                <rect
                  key={item.key}
                  x={barX}
                  y={PADDING.top + plotHeight - stackHeight - height}
                  width={barWidth}
                  height={height}
                  fill={item.color}
                />
              );
              stackHeight += height;
              return bar;
            })}
            {labelIndexes.has(index) ? (
              <text x={barX + barWidth / 2} y={CHART_HEIGHT - 8} textAnchor="middle" className="chart-date-label">
                {labelDate(point.date)}
              </text>
            ) : null}
          </g>
        );
      })}
    </svg>
  );
}

function Legend({ items }) {
  return (
    <ul className="chart-legend">
      {items.map((item) => (
        <li key={item.key}>
          <span style={{ backgroundColor: item.color }} aria-hidden="true" />
          {item.label}
        </li>
      ))}
    </ul>
  );
}

export default function DashboardCharts({ role, data, days, onDaysChange, loading, error, onRetry }) {
  const points = data?.points || [];
  const platform = role === 'SUPER_ADMIN';
  const activitySeries = platform
    ? [{ key: 'organizationsRegistered', label: 'Organizations registered', color: '#315f46' }]
    : [
      { key: 'scans', label: 'Scans', color: '#315f46' },
      { key: 'completedScans', label: 'Completed', color: '#2f6b45' },
      { key: 'failedScans', label: 'Failed', color: '#b42318' },
    ];

  return (
    <section className="dashboard-analytics" aria-labelledby="dashboard-analytics-heading">
      <div className="page-header analytics-header">
        <div>
          <p className="eyebrow">Historical trends</p>
          <h2 id="dashboard-analytics-heading">Dashboard analytics</h2>
        </div>
        <label className="analytics-range">
          Date range
          <select aria-label="Analytics date range" value={days} onChange={(event) => onDaysChange(Number(event.target.value))}>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
        </label>
      </div>

      {error ? (
        <div className="message-card error" role="alert">
          <p>{error}</p>
          <button type="button" className="secondary-button" onClick={onRetry}>Retry analytics</button>
        </div>
      ) : loading ? (
        <p className="muted" role="status">Loading historical analytics…</p>
      ) : data ? (
        <div className={`dashboard-chart-grid${platform ? ' platform-chart-grid' : ''}`}>
          <article className="data-card dashboard-chart-card">
            <div className="data-card-header">
              <div>
                <h3>{platform ? 'Organization registrations' : 'Scan activity'}</h3>
                <p className="muted">{labelDate(data.from)} – {labelDate(data.through)}</p>
              </div>
            </div>
            <Legend items={activitySeries} />
            <LineChart points={points} series={activitySeries} label={platform
              ? `Organization registrations over the last ${days} days`
              : `Scan activity over the last ${days} days`} />
          </article>

          {!platform ? (
            <article className="data-card dashboard-chart-card">
              <div className="data-card-header">
                <div>
                  <h3>Findings by severity</h3>
                  <p className="muted">Persisted findings by detection date</p>
                </div>
              </div>
              <Legend items={[
                { key: 'highFindings', label: 'High', color: '#b42318' },
                { key: 'mediumFindings', label: 'Medium', color: '#b54708' },
                { key: 'lowFindings', label: 'Low', color: '#2563a6' },
              ]} />
              <SeverityChart points={points} days={days} />
            </article>
          ) : null}
          <details className="analytics-data-table">
            <summary>View daily analytics data</summary>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Date</th>
                    {platform ? <th scope="col">Organizations registered</th> : (
                      <>
                        <th scope="col">Scans</th>
                        <th scope="col">Completed</th>
                        <th scope="col">Failed</th>
                        <th scope="col">High</th>
                        <th scope="col">Medium</th>
                        <th scope="col">Low</th>
                      </>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {points.map((point) => (
                    <tr key={point.date}>
                      <td>{point.date}</td>
                      {platform ? <td>{point.organizationsRegistered}</td> : (
                        <>
                          <td>{point.scans}</td>
                          <td>{point.completedScans}</td>
                          <td>{point.failedScans}</td>
                          <td>{point.highFindings}</td>
                          <td>{point.mediumFindings}</td>
                          <td>{point.lowFindings}</td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        </div>
      ) : (
        <div className="message-card">Historical analytics are unavailable.</div>
      )}
    </section>
  );
}
