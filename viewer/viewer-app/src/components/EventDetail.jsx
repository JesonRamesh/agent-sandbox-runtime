import { useEffect } from 'react';
import './EventDetail.css';

// Side panel showing the full payload of one kernel event. Open by clicking
// a row in KernelPanel; close via the × button or Esc.
//
// Why a separate component: KernelPanel rows must stay scannable, so the
// rich detail (full reason, matched_rule, comm/pid, raw kind) lives in this
// panel rather than inside each row.
export default function EventDetail({ event, onClose }) {
  useEffect(() => {
    if (!event) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [event, onClose]);

  if (!event) return null;

  const d = event.data || {};
  const verdict = event.type.endsWith('_blocked') ? 'block' : 'allow';
  const fmtTime = (ts) => {
    if (!ts && ts !== 0) return '—';
    const date = new Date(ts * 1000);
    return date.toLocaleTimeString([], { hour12: false }) + '.' +
      String(date.getMilliseconds()).padStart(3, '0');
  };

  // Render an ordered list of fact rows. Skip undefined/empty so the panel
  // doesn't print "matched_rule: " with nothing after it.
  const facts = [
    ['agent',        event.agent],
    ['pillar',       d.pillar],
    ['kind',         d.kind],
    ['verdict',      d.verdict || verdict],
    ['target',       d.target || d.hostname],
    ['process',      d.comm ? `${d.comm}${d.pid ? ' (pid ' + d.pid + ')' : ''}` : null],
    ['matched rule', d.matched_rule],
    ['reason code',  d.reason_code],
    ['observed',     fmtTime(event.ts)],
  ].filter(([, v]) => v !== undefined && v !== null && v !== '');

  return (
    <aside className={`event-detail event-detail--verdict-${verdict}`}>
      <header className="event-detail__header">
        <span className={`event-detail__verdict verdict-${verdict}`}>
          {verdict === 'block' ? 'BLOCKED' : 'ALLOWED'}
        </span>
        <span className={`event-detail__pillar pillar-${d.pillar || 'meta'}`}>
          {d.pillar || event.type}
        </span>
        <button type="button" className="event-detail__close" onClick={onClose} aria-label="close detail panel">
          ×
        </button>
      </header>
      <div className="event-detail__body">
        {d.reason && (
          <p className="event-detail__reason">{d.reason}</p>
        )}
        <table className="event-detail__facts">
          <tbody>
            {facts.map(([k, v]) => (
              <tr key={k}>
                <th>{k}</th>
                <td>{String(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <details className="event-detail__raw">
          <summary>raw event JSON</summary>
          <pre>{JSON.stringify(event, null, 2)}</pre>
        </details>
      </div>
    </aside>
  );
}
