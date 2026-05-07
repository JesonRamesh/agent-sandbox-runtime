import { useEffect, useState } from 'react';
import './SecurityPanel.css';

function secondsSince(ts) {
  if (!ts) return null;
  return Math.floor(Date.now() / 1000 - ts);
}

export default function SecurityPanel({ analysis, lastTs }) {
  const [age, setAge] = useState(() => secondsSince(lastTs));

  useEffect(() => {
    setAge(secondsSince(lastTs));
    if (!lastTs) return;
    const id = setInterval(() => setAge(secondsSince(lastTs)), 1000);
    return () => clearInterval(id);
  }, [lastTs]);

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
