import { useEffect, useRef } from 'react';
import './Panel.css';
import './EventRow.css';

function formatTime(ts) {
  if (!ts && ts !== 0) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false }) + '.' +
    String(d.getMilliseconds()).padStart(3, '0');
}

// One row's primary text (left of the expand chevron). The bridge transform
// fills `data.target` for every pillar; we just decorate it with an icon
// reflecting the verdict.
function renderTarget(event) {
  const d = event.data || {};
  const target = d.target || d.hostname || '(unknown)';
  if (event.type.endsWith('_blocked')) return `✗ ${target}`;
  if (event.type === 'stopped' || event.type === 'crashed') return target;
  return `✓ ${target}`;
}

// Map UI types to pillar keys for badge styling. Keep this in lockstep with
// the bridge transform's UI_KERNEL_TYPES.
const PILLAR_OF_TYPE = {
  net_allowed:  'net',  net_blocked:  'net',
  file_allowed: 'file', file_blocked: 'file',
  exec_allowed: 'exec', exec_blocked: 'exec',
  cred_allowed: 'cred', cred_blocked: 'cred',
};

export default function KernelPanel({ events, selectedEventId, onSelectEvent }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ block: 'end' });
    }
  }, [events.length]);

  return (
    <section className="panel">
      <header className="panel__header">
        <span className="panel__title">kernel events</span>
        <span className="panel__count">{events.length}</span>
      </header>
      <div className="panel__feed">
        {events.length === 0 ? (
          <div className="panel__empty">waiting for kernel events…</div>
        ) : (
          events.map((event) => {
            const d = event.data || {};
            const pillar = PILLAR_OF_TYPE[event.type] || 'meta';
            const verdict = event.type.endsWith('_blocked') ? 'block' : 'allow';
            const isSelected = selectedEventId === event._id;
            return (
              <button
                key={event._id}
                type="button"
                onClick={() => onSelectEvent && onSelectEvent(isSelected ? null : event._id)}
                className={
                  `event-row event-row--button` +
                  ` type-${event.type}` +
                  ` pillar-${pillar} verdict-${verdict}` +
                  (isSelected ? ' is-selected' : '')
                }
              >
                <span className="event-row__time">{formatTime(event.ts)}</span>
                <span className={`event-row__pillar pillar-${pillar}`}>{pillar}</span>
                <span className={`event-row__badge verdict-${verdict}`}>
                  {verdict === 'block' ? 'BLOCK' : 'ALLOW'}
                </span>
                <span className="event-row__content">
                  <span className="event-row__target">{renderTarget(event)}</span>
                  {d.reason && (
                    <span className="event-row__reason"> — {d.reason}</span>
                  )}
                </span>
              </button>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </section>
  );
}
