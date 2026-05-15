import { useEffect, useRef, useState } from 'react';
import './ConnectionTimeline.css';

const WINDOW_SEC = 60;
const W = 600, H = 56;

function timeX(ts: number, now: number) {
  const age = now - ts;
  return W - (age / WINDOW_SEC) * W;
}

interface ConnectionTimelineProps {
  kernelEvents: any[];
}

export default function ConnectionTimeline({ kernelEvents }: ConnectionTimelineProps) {
  const [now, setNow] = useState(() => Date.now() / 1000);
  const [hovered, setHovered] = useState<any>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  // Tick every second to slide events left
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(id);
  }, []);

  // Only show last 60s of connect_allowed + connect_blocked
  const visible = kernelEvents.filter((e) =>
    (e.type === 'connect_allowed' || e.type === 'connect_blocked') &&
    e.ts && (now - e.ts) <= WINDOW_SEC
  );

  const midY = H / 2;

  return (
    <div className="conn-timeline">
      <div className="conn-timeline__header">
        <span className="conn-timeline__title">Connection Timeline</span>
        <div className="conn-timeline__legend">
          <span className="conn-timeline__leg conn-timeline__leg--allowed">● Allowed</span>
          <span className="conn-timeline__leg conn-timeline__leg--blocked">● Blocked</span>
          <span className="conn-timeline__leg conn-timeline__leg--time">← 60s window</span>
        </div>
      </div>

      <div className="conn-timeline__body">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          className="conn-timeline__svg"
          onMouseLeave={() => setHovered(null)}
        >
          {/* Grid lines */}
          {[0, 15, 30, 45, 60].map((s) => {
            const x = W - (s / WINDOW_SEC) * W;
            return (
              <g key={s}>
                <line x1={x} y1={0} x2={x} y2={H}
                  stroke="rgba(255,255,255,0.04)" strokeWidth="1" strokeDasharray="3 4" />
                <text x={x} y={H - 2} textAnchor="middle"
                  fill="rgba(255,255,255,0.2)" fontSize="7" fontFamily="var(--mono)">
                  {s === 0 ? 'now' : `-${s}s`}
                </text>
              </g>
            );
          })}

          {/* Baseline */}
          <line x1={0} y1={midY} x2={W} y2={midY}
            stroke="rgba(255,255,255,0.06)" strokeWidth="1" />

          {/* "Now" sweep line */}
          <line x1={W} y1={0} x2={W} y2={H}
            stroke="rgba(59,130,246,0.3)" strokeWidth="1.5" />

          {/* Event dots */}
          {visible.map((e) => {
            const x = timeX(e.ts, now);
            const isBlocked = e.type === 'connect_blocked';
            const color = isBlocked ? '#ef4444' : '#10b981';
            const r = isBlocked ? 5 : 4;
            const isHov = hovered?._id === e._id;
            return (
              <g key={e._id}
                onMouseEnter={() => setHovered(e)}
                onMouseLeave={() => setHovered(null)}
                style={{ cursor: 'pointer' }}
              >
                {/* Glow ring */}
                <circle cx={x} cy={midY} r={r + 4}
                  fill="none"
                  stroke={color}
                  strokeWidth={isHov ? 1.5 : 0.5}
                  opacity={isHov ? 0.6 : 0.2}
                />
                {/* Main dot */}
                <circle cx={x} cy={midY} r={r}
                  fill={color}
                  opacity={isBlocked ? 0.9 : 0.8}
                  style={{ filter: `drop-shadow(0 0 ${isBlocked ? 4 : 3}px ${color})` }}
                />
                {/* Blocked: vertical spike */}
                {isBlocked && (
                  <line x1={x} y1={midY - r} x2={x} y2={midY - 16}
                    stroke={color} strokeWidth="1.5" opacity="0.5"
                  />
                )}
              </g>
            );
          })}
        </svg>

        {/* Tooltip */}
        {hovered && (
          <div className="conn-timeline__tooltip">
            <span className={`conn-timeline__tooltip-type conn-timeline__tooltip-type--${hovered.type === 'connect_blocked' ? 'blocked' : 'allowed'}`}>
              {hovered.type === 'connect_blocked' ? 'Blocked' : 'Allowed'}
            </span>
            <span className="conn-timeline__tooltip-host">
              {hovered.data?.hostname || `${hovered.data?.dst_ip}:${hovered.data?.dst_port}`}
            </span>
            <span className="conn-timeline__tooltip-age">
              {Math.round(now - hovered.ts)}s ago
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
