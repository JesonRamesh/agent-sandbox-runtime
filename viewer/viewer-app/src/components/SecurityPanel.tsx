import { useEffect, useState } from 'react';
import './SecurityPanel.css';

// Analysis payload left as `any` — fully typed in T12.
interface Analysis {
  threatLevel?: 'low' | 'medium' | 'high' | 'critical' | string;
  summary?: string;
  concerns?: string[];
  recommendation?: string;
}

interface Props {
  analysis?: Analysis | null;
  lastTs?: number | null;
}

function secondsSince(ts: number | null | undefined): number | null {
  if (!ts) return null;
  return Math.floor(Date.now() / 1000 - ts);
}

export default function SecurityPanel({ analysis, lastTs }: Props) {
  // Tick counter drives re-renders so `age` (computed below) stays fresh.
  // Storing age in state would force a synchronous setState inside the
  // effect body to resync on `lastTs` change — disallowed by react-hooks.
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!lastTs) return;
    const id = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(id);
  }, [lastTs]);
  const age = secondsSince(lastTs);

  const level = analysis?.threatLevel || 'low';

  return (
    <div className="security-panel">
      <div className="security-panel__header">
        <span className="security-panel__title">security analysis</span>
        {analysis && (
          <span className={`security-panel__badge security-panel__badge--${level}`}>
            {level}
          </span>
        )}
      </div>

      {!analysis ? (
        <span className="security-panel__empty">awaiting first analysis…</span>
      ) : (
        <>
          <div className="security-panel__summary">{analysis.summary}</div>

          {analysis.concerns && analysis.concerns.length > 0 && (
            <div className="security-panel__concerns">
              {analysis.concerns.map((c, i) => (
                <span key={i} className="security-panel__concern">{c}</span>
              ))}
            </div>
          )}

          {analysis.recommendation && (
            <div className="security-panel__recommendation">
              {analysis.recommendation}
            </div>
          )}

          <div className="security-panel__footer">
            {age !== null ? `Last analysed ${age}s ago` : 'Just analysed'}
          </div>
        </>
      )}
    </div>
  );
}
