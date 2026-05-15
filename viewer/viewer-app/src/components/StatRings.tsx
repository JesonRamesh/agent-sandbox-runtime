import './StatRings.css';

const W = 220, H = 120, CX = 110, CY = 112, R = 88, STROKE = 12;

// Convert polar angle (degrees) to SVG x,y on the arc
function polar(cx: number, cy: number, r: number, deg: number) {
  const rad = (deg * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

// Build SVG arc path for a semi-circle segment
function arcPath(cx: number, cy: number, r: number, startDeg: number, endDeg: number) {
  const s = polar(cx, cy, r, startDeg);
  const e = polar(cx, cy, r, endDeg);
  const large = Math.abs(endDeg - startDeg) > 180 ? 1 : 0;
  return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
}

// Semi-arc spans from 180° (left) to 0° (right) = top half
const START = 180, END = 360;

interface SplitArcProps {
  leftVal: number;
  rightVal: number;
  leftColor: string;
  rightColor: string;
  leftLabel: string;
  rightLabel: string;
  centerTop: string;
  centerBottom: string;
  dimmed?: boolean;
}

function SplitArc({ leftVal, rightVal, leftColor, rightColor, leftLabel, rightLabel, centerTop, centerBottom }: SplitArcProps) {
  const total = leftVal + rightVal;
  const leftPct  = total > 0 ? leftVal  / total : 0.5;
  const rightPct = total > 0 ? rightVal / total : 0.5;
  const splitDeg = START + leftPct * (END - START);

  // Track (background)
  const trackPath = arcPath(CX, CY, R, START, END);
  // Left arc
  const leftPath  = arcPath(CX, CY, R, START, splitDeg);
  // Right arc
  const rightPath = arcPath(CX, CY, R, splitDeg, END);

  const leftPct100  = Math.round(leftPct  * 100);
  const rightPct100 = Math.round(rightPct * 100);

  return (
    <div className="split-arc">
      <svg width={W} height={H} className="split-arc__svg" overflow="visible">
        <defs>
          <filter id="glow-l">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="glow-r">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Track */}
        <path d={trackPath} fill="none" stroke="var(--border-subtle)" strokeWidth={STROKE} strokeLinecap="round" />

        {/* Left arc segment */}
        {leftPct > 0.01 && (
          <path d={leftPath} fill="none" stroke={leftColor} strokeWidth={STROKE} strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 5px ${leftColor})`, transition: 'all 600ms cubic-bezier(0.4,0,0.2,1)' }}
          />
        )}

        {/* Right arc segment */}
        {rightPct > 0.01 && (
          <path d={rightPath} fill="none" stroke={rightColor} strokeWidth={STROKE} strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 5px ${rightColor})`, transition: 'all 600ms cubic-bezier(0.4,0,0.2,1)' }}
          />
        )}

        {/* Split divider dot */}
        {total > 0 && (() => {
          const p = polar(CX, CY, R, splitDeg);
          return <circle cx={p.x} cy={p.y} r="4" fill="var(--bg-page)" stroke="var(--border-active)" strokeWidth="1.5" />;
        })()}

        {/* Centre: ratio */}
        <text x={CX} y={CY - 18} textAnchor="middle" className="split-arc__ratio-top" fill="var(--text-primary)">
          {centerTop}
        </text>
        <text x={CX} y={CY - 2} textAnchor="middle" className="split-arc__ratio-bottom" fill="var(--text-muted)">
          {centerBottom}
        </text>
      </svg>

      {/* Legend row */}
      <div className="split-arc__legend">
        <div className="split-arc__leg">
          <span className="split-arc__leg-dot" style={{ background: leftColor }} />
          <span className="split-arc__leg-val" style={{ color: leftColor }}>{leftVal}</span>
          <span className="split-arc__leg-label">{leftLabel}</span>
          <span className="split-arc__leg-pct">{leftPct100}%</span>
        </div>
        <div className="split-arc__leg">
          <span className="split-arc__leg-dot" style={{ background: rightColor }} />
          <span className="split-arc__leg-val" style={{ color: rightColor }}>{rightVal}</span>
          <span className="split-arc__leg-label">{rightLabel}</span>
          <span className="split-arc__leg-pct">{rightPct100}%</span>
        </div>
      </div>
    </div>
  );
}

function formatUptime(seconds: number) {
  const s = Math.max(0, Math.floor(seconds || 0));
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const rm = m % 60;
  const rs = s % 60;
  if (h > 0) return `${h}h ${rm.toString().padStart(2,'0')}m`;
  if (m === 0) return `${s}s`;
  return `${m}m ${rs.toString().padStart(2, '0')}s`;
}

interface StatRingsProps {
  stats?: { toolCalls?: number; allowed?: number; blocked?: number; uptime?: number };
  blockedPulseKey?: number;
}

export default function StatRings({ stats }: StatRingsProps) {
  const { toolCalls = 0, allowed = 0, blocked = 0, uptime = 0 } = stats || {};
  const safe = toolCalls - blocked;

  return (
    <div className="stat-rings">
      {/* Card 1: Connections — allowed vs blocked */}
      <div className="stat-rings__card">
        <SplitArc
          leftVal={allowed}  leftColor="var(--accent-emerald)"  leftLabel="allowed"
          rightVal={blocked} rightColor="var(--accent-crimson)" rightLabel="blocked"
          centerTop={`${allowed}:${blocked}`}
          centerBottom="allow:block"
        />
        <div className="stat-rings__card-label">Connections</div>
      </div>

      {/* Card 2: Agent activity — safe vs injected */}
      <div className="stat-rings__card">
        <SplitArc
          leftVal={Math.max(safe, 0)} leftColor="var(--accent-blue)"  leftLabel="safe"
          rightVal={blocked}          rightColor="var(--accent-amber)" rightLabel="injected"
          centerTop={`${toolCalls}`}
          centerBottom="tool calls"
        />
        <div className="stat-rings__card-label">Agent Activity</div>
      </div>

      {/* Card 3: Session — uptime + total events */}
      <div className="stat-rings__card">
        <SplitArc
          leftVal={allowed + Math.max(safe,0)} leftColor="var(--accent-purple)" leftLabel="clean"
          rightVal={blocked}                   rightColor="var(--accent-crimson)" rightLabel="threats"
          centerTop={formatUptime(uptime)}
          centerBottom="uptime"
        />
        <div className="stat-rings__card-label">Session</div>
      </div>
    </div>
  );
}