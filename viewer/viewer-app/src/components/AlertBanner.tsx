import './AlertBanner.css';

interface Props {
  hostname?: string;
  reason?: string;
  onDismiss?: () => void;
}

export default function AlertBanner({ hostname, reason, onDismiss }: Props) {
  return (
    <div className="alert-banner" role="alert">
      <span className="alert-banner__icon">⚠</span>
      <span className="alert-banner__text">
        Injection attack blocked by kernel —{' '}
        <strong>{hostname || 'unknown host'}</strong>
        {reason ? ` (${reason})` : ''}
      </span>
      <button
        type="button"
        className="alert-banner__dismiss"
        aria-label="dismiss alert"
        onClick={onDismiss}
      >
        ✕
      </button>
    </div>
  );
}
