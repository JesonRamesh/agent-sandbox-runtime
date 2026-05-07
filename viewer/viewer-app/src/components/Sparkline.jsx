import { useEffect, useRef, useState } from 'react';
import './Sparkline.css';

const BUCKETS   = 30;   // 30 buckets × 2s = 60s window
const TICK_MS   = 2000;

export default function Sparkline({ llmEvents, kernelEvents }) {
  // Each bucket: { total, blocked }
  const [buckets, setBuckets] = useState(() =>
    Array(BUCKETS).fill(null).map(() => ({ total: 0, blocked: 0 }))
  );
  const lastTotalRef   = useRef(0);
  const lastBlockedRef = useRef(0);

  // On new events, push delta into current (last) bucket
  useEffect(() => {
    const total   = llmEvents.length + kernelEvents.length;
    const blocked = kernelEvents.filter((e) => e.type === 'connect_blocked').length;
    const dTotal   = total   - lastTotalRef.current;
    const dBlocked = blocked - lastBlockedRef.current;
    lastTotalRef.current   = total;
    lastBlockedRef.current = blocked;
    if (dTotal <= 0 && dBlocked <= 0) return;
    setBuckets((prev) => {
      const next = [...prev];
      next[next.length - 1] = {
        total:   next[next.length - 1].total   + dTotal,
        blocked: next[next.length - 1].blocked + dBlocked,
      };
      return next;
    });
  }, [llmEvents.length, kernelEvents.length]);

  // Slide buckets left every 2s
  useEffect(() => {
    const id = setInterval(() => {
      setBuckets((prev) => [...prev.slice(1), { total: 0, blocked: 0 }]);
    }, TICK_MS);
    return () => clearInterval(id);
  }, []);

  const W = 160, H = 34;
  const BAR_W = Math.floor(W / BUCKETS) - 1; // bar width with 1px gap
  const max = Math.max(...buckets.map((b) => b.total), 1);
  const hasActivity = buckets.some((b) => b.total > 0);
  const BASE_Y = H - 3; // baseline y
  const MIN_H = 3;      // minimum spike height so even 1 event is visible

  return (
    <div className="sparkline">
      <svg width={W} height={H} className="sparkline__svg">
        {/* Baseline */}
        <line x1="0" y1={BASE_Y} x2={W} y2={BASE_Y}
          stroke="rgba(255,255,255,0.08)" strokeWidth="1" />

        {!hasActivity && (
          <line x1="0" y1={BASE_Y} x2={W} y2={BASE_Y}
            stroke="rgba(16,185,129,0.3)" strokeWidth="1" strokeDasharray="4 4" />
        )}

        {/* Per-bucket bars */}
        {buckets.map((b, i) => {
          if (b.total === 0) return null;
          const isRed   = b.blocked > 0;
          const color   = isRed ? '#ef4444' : '#10b981';
          const glow    = isRed ? '#ef4444' : '#10b981';
          // Height scales with total, min MIN_H, max H-BASE_Y-2
          const barH    = MIN_H + Math.round((b.total / max) * (BASE_Y - MIN_H - 4));
          const x       = i * (BAR_W + 1);
          const y       = BASE_Y - barH;
          return (
            <g key={i} style={{ filter: `drop-shadow(0 0 ${isRed ? 5 : 3}px ${glow})` }}>
              {/* Vertical spike */}
              <rect
                x={x} y={y}
                width={BAR_W} height={barH}
                rx="1"
                fill={color}
                opacity={isRed ? 0.85 : 0.7}
              />
              {/* Bright tip */}
              <rect
                x={x} y={y}
                width={BAR_W} height={2}
                rx="1"
                fill={color}
                opacity="1"
              />
            </g>
          );
        })}
      </svg>
      <span className="sparkline__label">activity</span>
    </div>
  );
}
