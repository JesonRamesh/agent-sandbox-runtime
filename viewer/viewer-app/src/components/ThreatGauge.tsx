import { useEffect, useState } from 'react';
import type { SecurityAnalysis } from '../types/events';
import './ThreatGauge.css';

function secondsSince(ts?: number | null): number | null {
  if (!ts) return null;
  return Math.floor(Date.now() / 1000 - ts);
}

// Map threat level to a 0-1 position on the arc (0=left=low, 1=right=critical)
const LEVEL_POS: Record<string, number> = { low: 0.08, medium: 0.38, high: 0.65, critical: 0.92 };
const LEVEL_COLOUR: Record<string, string> = {
  low:      '#10b981',
  medium:   '#f59e0b',
  high:     '#ef4444',
  critical: '#ef4444',
};
const LEVEL_LABEL: Record<string, string> = {
  low:      'LOW',
  medium:   'MEDIUM',
  high:     'HIGH',
  critical: 'CRITICAL',
};

// Build SVG arc path for a semi-circle gauge
// cx,cy = centre, r = radius, startAngle/endAngle in degrees
function arcPath(cx: number, cy: number, r: number, startDeg: number, endDeg: number) {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const x1 = cx + r * Math.cos(toRad(startDeg));
  const y1 = cy + r * Math.sin(toRad(startDeg));
  const x2 = cx + r * Math.cos(toRad(endDeg));
  const y2 = cy + r * Math.sin(toRad(endDeg));
  const large = Math.abs(endDeg - startDeg) > 180 ? 1 : 0;
  return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
}

// Needle tip coordinates from centre given angle in degrees
function needleCoords(cx: number, cy: number, length: number, deg: number) {
  const rad = (deg * Math.PI) / 180;
  return {
    x: cx + length * Math.cos(rad),
    y: cy + length * Math.sin(rad),
  };
}

interface ThreatGaugeProps {
  analysis?: SecurityAnalysis | null;
  lastTs?: number | null;
}

export default function ThreatGauge({ analysis, lastTs }: ThreatGaugeProps) {
  const [age, setAge] = useState(() => secondsSince(lastTs));

  useEffect(() => {
    setAge(secondsSince(lastTs));
    if (!lastTs) return;
    const id = setInterval(() => setAge(secondsSince(lastTs)), 1000);
    return () => clearInterval(id);
  }, [lastTs]);

  const level    = analysis?.threatLevel || 'low';
  const pos      = LEVEL_POS[level] ?? 0.08;
  const colour   = LEVEL_COLOUR[level];
  const isCrit   = level === 'critical';

  // Gauge arc: 180° semi-circle, starts at left (180°), ends at right (0°)
  // We use 185→355 so the arc doesn't perfectly touch the horizontal
  const START_DEG = 185;
  const END_DEG   = 355;
  const ARC_SPAN  = END_DEG - START_DEG;   // 170°
  const cx = 110, cy = 90, r = 70;

  // Needle angle
  const needleDeg = START_DEG + pos * ARC_SPAN;
  const needleTip = needleCoords(cx, cy, 58, needleDeg);
  const needleBase1 = needleCoords(cx, cy, 8, needleDeg + 90);
  const needleBase2 = needleCoords(cx, cy, 8, needleDeg - 90);

  // Gradient arc segments (track divided into 4 zones)
  const zones = [
    { from: 0,    to: 0.28, color: '#10b981' },
    { from: 0.28, to: 0.55, color: '#f59e0b' },
    { from: 0.55, to: 0.78, color: '#ef4444' },
    { from: 0.78, to: 1.0,  color: '#dc2626' },
  ];

  return (
    <div className={`threat-gauge ${isCrit ? 'threat-gauge--critical' : ''}`}>
      <div className="threat-gauge__header">
        <span className="threat-gauge__title">Threat Level</span>
        {analysis && (
          <span className={`threat-gauge__badge threat-gauge__badge--${level}`}>
            {LEVEL_LABEL[level]}
          </span>
        )}
      </div>

      <div className="threat-gauge__body">
        {/* SVG Gauge */}
        <svg width="220" height="110" className="threat-gauge__svg">
          {/* Zone arcs (track) */}
          {zones.map((z, i) => (
            <path
              key={i}
              d={arcPath(cx, cy, r,
                START_DEG + z.from * ARC_SPAN,
                START_DEG + z.to   * ARC_SPAN)}
              fill="none"
              stroke={z.color}
              strokeWidth="10"
              strokeLinecap="butt"
              opacity="0.18"
            />
          ))}

          {/* Active arc up to needle position */}
          <path
            d={arcPath(cx, cy, r, START_DEG, needleDeg)}
            fill="none"
            stroke={colour}
            strokeWidth="10"
            strokeLinecap="round"
            opacity="0.7"
            style={{
              transition: 'd 600ms cubic-bezier(0.4,0,0.2,1)',
              filter: `drop-shadow(0 0 5px ${colour})`,
            }}
          />

          {/* Zone tick marks */}
          {[0, 0.28, 0.55, 0.78, 1].map((t, i) => {
            const deg = START_DEG + t * ARC_SPAN;
            const inner = needleCoords(cx, cy, r - 6, deg);
            const outer = needleCoords(cx, cy, r + 6, deg);
            return (
              <line
                key={i}
                x1={inner.x} y1={inner.y}
                x2={outer.x} y2={outer.y}
                stroke="var(--border-active)"
                strokeWidth="1.5"
              />
            );
          })}

          {/* Needle */}
          <polygon
            points={`${needleTip.x},${needleTip.y} ${needleBase1.x},${needleBase1.y} ${needleBase2.x},${needleBase2.y}`}
            fill={colour}
            opacity="0.9"
            style={{ transition: 'points 600ms cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 3px ${colour})` }}
          />

          {/* Centre pivot circle */}
          <circle cx={cx} cy={cy} r="5" fill={colour} opacity="0.9" />
          <circle cx={cx} cy={cy} r="3" fill="var(--bg-page)" />

          {/* Zone labels */}
          {([
            { t: 0.05,  text: 'LOW',  anchor: 'start'  },
            { t: 0.5,   text: 'MED',  anchor: 'middle' },
            { t: 0.95,  text: 'CRIT', anchor: 'end'    },
          ] as const).map((lbl, i) => {
            const deg = START_DEG + lbl.t * ARC_SPAN;
            const pos = needleCoords(cx, cy, r + 16, deg);
            return (
              <text
                key={i}
                x={pos.x} y={pos.y}
                textAnchor={lbl.anchor}
                fill="var(--text-muted)"
                fontSize="8"
                fontFamily="var(--mono)"
                fontWeight="600"
                letterSpacing="0.5"
              >
                {lbl.text}
              </text>
            );
          })}
        </svg>

        {/* Right side: analysis text */}
        <div className="threat-gauge__info">
          {!analysis ? (
            <span className="threat-gauge__empty">awaiting first analysis…</span>
          ) : (
            <>
              <p className="threat-gauge__summary">{analysis.summary}</p>

              {(analysis.concerns?.length ?? 0) > 0 && (
                <ul className="threat-gauge__concerns">
                  {analysis.concerns!.map((c: string, i: number) => (
                    <li key={i} className="threat-gauge__concern">{c}</li>
                  ))}
                </ul>
              )}

              {analysis.recommendation && (
                <div className="threat-gauge__rec">{analysis.recommendation}</div>
              )}

              <div className="threat-gauge__age">
                {age !== null ? `analysed ${age}s ago` : 'just analysed'}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}