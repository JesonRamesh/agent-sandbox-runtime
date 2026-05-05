import './Sidebar.css';

function formatUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  const m = Math.floor(s / 60);
  const r = s % 60;
  if (m === 0) return `${r}s`;
  return `${m}m ${r.toString().padStart(2, '0')}s`;
}

function AgentStatusDot({ events }) {
  if (!events || events.length === 0) return <span className="sidebar__agent-dot sidebar__agent-dot--idle" />;
  const last = events[events.length - 1];
  if (last.type === 'crashed') return <span className="sidebar__agent-dot sidebar__agent-dot--crashed" />;
  if (last.type === 'stopped') return <span className="sidebar__agent-dot sidebar__agent-dot--done" />;
  return <span className="sidebar__agent-dot sidebar__agent-dot--running" />;
}

function AgentStatusLabel({ events }) {
  if (!events || events.length === 0) return <span className="sidebar__agent-status">idle</span>;
  const last = events[events.length - 1];
  if (last.type === 'crashed') return <span className="sidebar__agent-status sidebar__agent-status--crashed">crashed</span>;
  if (last.type === 'stopped') return <span className="sidebar__agent-status sidebar__agent-status--done">completed</span>;
  return <span className="sidebar__agent-status sidebar__agent-status--running">running</span>;
}

export default function Sidebar({
  agents,
  activeAgent,
  onSelectAgent,
  llmEvents,
  kernelEvents,
  stats,
  wsStatus,
  activeTab,
  onSelectTab,
}) {
  const connected = wsStatus === 'connected';

  const navItems = [
    { id: 'events',   icon: '⬡', label: 'Events' },
    { id: 'workflow', icon: '◈', label: 'Workflow' },
  ];

  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar__brand">
        <span className="sidebar__brand-icon">▲</span>
        <span className="sidebar__brand-name">AgentOS</span>
      </div>

      {/* WS status */}
      <div className={`sidebar__ws ${connected ? 'sidebar__ws--connected' : 'sidebar__ws--disconnected'}`}>
        <span className="sidebar__ws-dot" />
        <span className="sidebar__ws-label">{connected ? 'Live' : 'Offline'}</span>
        <span className="sidebar__ws-uptime">{formatUptime(stats?.uptime)}</span>
      </div>

      {/* Nav */}
      <nav className="sidebar__nav">
        <div className="sidebar__nav-label">Views</div>
        {navItems.map((item) => (
          <button
            key={item.id}
            className={`sidebar__nav-item ${activeTab === item.id ? 'is-active' : ''}`}
            onClick={() => onSelectTab(item.id)}
          >
            <span className="sidebar__nav-icon">{item.icon}</span>
            <span className="sidebar__nav-text">{item.label}</span>
          </button>
        ))}
      </nav>

      {/* Agents */}
      <div className="sidebar__section">
        <div className="sidebar__nav-label">Agents</div>
        {agents.length === 0 ? (
          <div className="sidebar__empty">No agents yet…</div>
        ) : (
          agents.map((agent) => {
            const agentLlm = llmEvents.filter((e) => e.agent === agent);
            return (
              <button
                key={agent}
                className={`sidebar__agent ${activeAgent === agent ? 'is-active' : ''}`}
                onClick={() => onSelectAgent(agent)}
              >
                <AgentStatusDot events={agentLlm} />
                <span className="sidebar__agent-name">{agent}</span>
                <AgentStatusLabel events={agentLlm} />
              </button>
            );
          })
        )}
      </div>

      {/* Quick counts */}
      <div className="sidebar__counts">
        <div className="sidebar__count-row">
          <span className="sidebar__count-label">Tool calls</span>
          <span className="sidebar__count-value">{stats?.toolCalls ?? 0}</span>
        </div>
        <div className="sidebar__count-row">
          <span className="sidebar__count-label">Allowed</span>
          <span className="sidebar__count-value sidebar__count-value--good">{stats?.allowed ?? 0}</span>
        </div>
        <div className="sidebar__count-row">
          <span className="sidebar__count-label">Blocked</span>
          <span className={`sidebar__count-value ${(stats?.blocked ?? 0) > 0 ? 'sidebar__count-value--bad' : ''}`}>
            {stats?.blocked ?? 0}
          </span>
        </div>
      </div>

      {/* Policy badge */}
      <div className="sidebar__policy">
        <span className="sidebar__policy-icon">🛡</span>
        <span className="sidebar__policy-text">eBPF Enforcing</span>
      </div>
    </aside>
  );
}