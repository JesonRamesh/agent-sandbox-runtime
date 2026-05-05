import { useEffect, useRef, useState } from 'react';
import './Sparkline.css';

const WINDOW_SEC = 60;   // track last 60 seconds
const BUCKETS    = 30;   // one bucket per 2 seconds

export default function Sparkline({ llmEvents, kernelEvents }) {
  // buckets[i] = event count in that 2s window
  const [buckets, setBuckets] = useState(() => Array(BUCKETS).fill(0));
  const lastCountRef = useRef(0);

  useEffect(() => {
    const total = llmEvents.length + kernelEvents.length;
    const delta = total - lastCountRef.current;
    lastCountRef.current = total;
    if (delta <= 0) return;

    setBuckets((prev) => {
      const next = [...prev.slice(1), delta];
      return next;
    });
  }, [llmEvents.length, kernelEvents.length]);

  // Slide buckets left every 2s regardless
  useEffect(() => {
    const id = setInterval(() => {
      setBuckets((prev) => [...prev.slice(1), 0]);
    }, 2000);
    return () => clearInterval(id);
  }, []);

  const W = 160, H = 32;
  const max = Math.max(...buckets, 1);
  const pts = buckets.map((v, i) => {
    const x = (i / (BUCKETS - 1)) * W;
    const y = H - (v / max) * (H - 4) - 2;
    return `${x},${y}`;
  }).join(' ');

  // Area fill path
  const areaFirst = `0,${H}`;
  const areaLast  = `${W},${H}`;
  const area = `${areaFirst} ${pts} ${areaLast}`;

  const hasActivity = buckets.some((b) => b > 0);

  return (
    <div className="sparkline">
      <svg width={W} height={H} className="sparkline__svg">
        <defs>
          <linearGradient id="spark-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="var(--accent-blue)" stopOpacity="0.25" />
            <stop offset="100%" stopColor="var(--accent-blue)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {/* Area fill */}
        {hasActivity && (
          <polygon points={area} fill="url(#spark-grad)" />
        )}
        {/* Line */}
        {hasActivity && (
          <polyline
            points={pts}
            fill="none"
            stroke="var(--accent-blue)"
            strokeWidth="1.5"
            strokeLinejoin="round"
            strokeLinecap="round"
            style={{ filter: 'drop-shadow(0 0 3px var(--accent-blue))' }}
          />
        )}
        {/* Flat baseline when idle */}
        {!hasActivity && (
          <line x1="0" y1={H - 2} x2={W} y2={H - 2}
            stroke="var(--border-active)" strokeWidth="1" strokeDasharray="4 4" />
        )}
      </svg>
      <span className="sparkline__label">activity</span>
    </div>
  );
}
