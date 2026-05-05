import { useEffect, useRef } from 'react';
import './Panel.css';
import './EventRow.css';

function formatTime(ts) {
  if (!ts && ts !== 0) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false }) + '.' +
    String(d.getMilliseconds()).padStart(3, '0');
}

function getLabel(event) {
  switch (event.type) {
    case 'connect_attempt': return 'Connection attempt';
    case 'connect_allowed': return 'Connection permitted';
    case 'connect_blocked': return 'Connection refused by kernel';
    default:                return event.type;
  }
}

function getDetail(event) {
  const d = event.data || {};
  switch (event.type) {
    case 'connect_attempt': {
      const host = d.hostname ? ` · ${d.hostname}` : '';
      return `→ ${d.dst_ip || '?'}:${d.dst_port || '?'}${host}`;
    }
    case 'connect_allowed':
      return [d.hostname, d.reason].filter(Boolean).join(' · ');
    case 'connect_blocked':
      return [d.hostname, d.reason].filter(Boolean).join(' · ');
    default:
      return '';
  }
}

export default function KernelPanel({ events }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ block: 'end' });
    }
  }, [events.length]);

  return (
    <section className="panel">
      <header className="panel__header">
        <span className="panel__title">
          <span className="panel__badge panel__badge--kernel">KERNEL</span>
          Network events
        </span>
        <span className="panel__count">{events.length}</span>
      </header>
      <div className="panel__feed">
        {events.length === 0 ? (
          <div className="panel__empty">waiting for kernel events…</div>
        ) : (
          events.map((event) => {
            const label  = getLabel(event);
            const detail = getDetail(event);
            return (
              <div key={event._id} className={`event-row event-row--two-line type-${event.type}`}>
                <span className="event-row__time">{formatTime(event.ts)}</span>
                <span className="event-row__body">
                  <span className="event-row__label">{label}</span>
                  {detail && <span className="event-row__detail">{detail}</span>}
                </span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </section>
  );
}
