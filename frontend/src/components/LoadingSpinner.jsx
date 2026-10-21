export default function LoadingSpinner({ label = 'Loading...' }) {
  return (
    <div className="loading-panel" role="status" aria-live="polite">
      <div className="spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}
