import './StatRings.css';

// Animated SVG donut ring
function Ring({ value, total, color, bgColor = 'var(--border-subtle)', size = 80, stroke = 8, label, sublabel, children }) {
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const pct = total > 0 ? Math.min(value / total, 1) : 0;
  const dash = pct * circ;
  const gap  = circ - dash;

  return (
    <div className="stat-ring">
      <svg width={size} height={size} className="stat-ring__svg">
        {/* Track */}
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke={bgColor}
          strokeWidth={stroke}
        />
        {/* Fill */}
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${gap}`}
          strokeDashoffset={circ / 4}
          style={{ transition: 'stroke-dasharray 600ms cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 4px ${color})` }}
        />
        {/* Centre value */}
        <text
          x={size / 2} y={size / 2}
          textAnchor="middle" dominantBaseline="central"
          className="stat-ring__val"
          fill={color}
        >
          {value}
        </text>
      </svg>
      <div className="stat-ring__labels">
        <span className="stat-ring__label">{label}</span>
        {sublabel && <span className="stat-ring__sublabel">{sublabel}</span>}
        {children}
      </div>
    </div>
  );
}

function formatUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  const m = Math.floor(s / 60);
  const r = s % 60;
  if (m === 0) return `${r}s`;
  return `${m}m ${r.toString().padStart(2, '0')}s`;
}

export default function StatRings({ stats, blockedPulseKey }) {
  const { toolCalls = 0, allowed = 0, blocked = 0, uptime = 0 } = stats || {};
  const totalConn = allowed + blocked;

  return (
    <div className="stat-rings">
      {/* Ring 1: Connections allowed vs blocked */}
      <div className="stat-rings__card">
        <div className="stat-rings__rings">
          <Ring
            value={allowed}
            total={totalConn || 1}
            color="var(--accent-emerald)"
            size={110} stroke={9}
            label="Allowed"
          />
          <Ring
            value={blocked}
            total={totalConn || 1}
            color="var(--accent-crimson)"
            size={110} stroke={9}
            label="Blocked"
          />
        </div>
        <div className="stat-rings__card-label">Connections</div>
      </div>

      {/* Ring 2: Tool calls */}
      <div className="stat-rings__card">
        <div className="stat-rings__rings">
          <Ring
            value={toolCalls}
            total={Math.max(toolCalls, 10)}
            color="var(--accent-blue)"
            size={110} stroke={9}
            label="Tool calls"
          />
          <Ring
            value={blocked}
            total={Math.max(toolCalls, 1)}
            color="var(--accent-amber)"
            size={110} stroke={9}
            label="Injected"
          />
        </div>
        <div className="stat-rings__card-label">Agent Activity</div>
      </div>

      {/* Ring 3: Session health — uptime arc (max 300s = full circle) */}
      <div className="stat-rings__card stat-rings__card--single">
        <Ring
          value={toolCalls + allowed}
          total={Math.max(toolCalls + allowed + blocked, 1)}
          color="var(--accent-purple)"
          size={110} stroke={9}
          label="Events"
          sublabel={`${toolCalls + allowed + blocked} total`}
        />
        <div className="stat-rings__uptime">
          <span className="stat-rings__uptime-val">{formatUptime(uptime)}</span>
          <span className="stat-rings__uptime-label">uptime</span>
        </div>
        <div className="stat-rings__card-label">Session</div>
      </div>
    </div>
  );
}