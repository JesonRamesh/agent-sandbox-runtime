import './Header.css';
import Sparkline from './Sparkline.jsx';

export default function Header({ wsStatus, llmEvents, kernelEvents }) {
  const connected = wsStatus === 'connected';
  return (
    <header className="header">
      <div className="header__brand">
        <span className="header__logo">▲</span>
        <h1 className="header__title">AgentOS</h1>
      </div>
      <Sparkline llmEvents={llmEvents || []} kernelEvents={kernelEvents || []} />
      <div className={`header__status ${connected ? 'is-connected' : 'is-disconnected'}`}>
        <span className="header__dot" />
        <span className="header__status-label">
          ws {connected ? 'connected' : 'disconnected'}
        </span>
      </div>
    </header>
  );
}
