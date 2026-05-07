import './Header.css';

export default function Header({ wsStatus, onReset, eventCount = 0 }) {
  const connected = wsStatus === 'connected';
  return (
    <header className="header">
      <div className="header__brand">
        <span className="header__logo">▲</span>
        <h1 className="header__title">Agent Sandbox Viewer</h1>
        <span className="header__sub">P5 · process viewer</span>
      </div>
      <div className="header__actions">
        <button
          type="button"
          className="header__reset"
          onClick={onReset}
          disabled={eventCount === 0}
          title={
            eventCount === 0
              ? 'no events to clear'
              : `clear all ${eventCount} event${eventCount === 1 ? '' : 's'} and reset the dashboard`
          }
        >
          ↺ reset
        </button>
        <div className={`header__status ${connected ? 'is-connected' : 'is-disconnected'}`}>
          <span className="header__dot" />
          <span className="header__status-label">
            ws {connected ? 'connected' : 'disconnected'}
          </span>
        </div>
      </div>
    </header>
  );
}
