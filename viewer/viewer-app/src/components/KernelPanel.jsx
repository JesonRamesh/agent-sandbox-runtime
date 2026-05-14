import { useState } from 'react';
import './Panel.css';
import './EventRow.css';
import './EventCard.css';

function formatTime(ts) {
  if (!ts && ts !== 0) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false }) + '.' +
    String(d.getMilliseconds()).padStart(3, '0');
}

// Pillar labels: NET / FILE / EXEC / CRED come straight off the new
// pillar-aware event types emitted by viewer/server/transform.js.
const PILLAR_LABEL = {
  net:  'Network',
  file: 'Filesystem',
  exec: 'Exec',
  cred: 'Credentials',
};

function getLabel(event) {
  switch (event.type) {
    case 'connect_attempt': return 'Connection attempt';
    case 'connect_allowed': return 'Connection permitted';
    case 'connect_blocked': return 'Connection refused by kernel';
  }
  // pillar_<allow|block>  →  "<Pillar> permitted/refused by kernel"
  const m = /^([a-z]+)_(allowed|blocked)$/.exec(event.type);
  if (m) {
    const pillar = PILLAR_LABEL[m[1]] || m[1];
    return m[2] === 'allowed' ? `${pillar} permitted` : `${pillar} refused by kernel`;
  }
  return event.type;
}

function getDetail(event) {
  const d = event.data || {};
  switch (event.type) {
    case 'connect_attempt': {
      const host = d.hostname ? ` · ${d.hostname}` : '';
      return `→ ${d.dst_ip || '?'}:${d.dst_port || '?'}${host}`;
    }
    case 'connect_allowed':
    case 'connect_blocked':
      return [d.hostname, d.reason].filter(Boolean).join(' · ');
  }
  // Pillar-aware events: bridge fills `data.target` for every kind. Fall
  // back to dst_ip:dst_port (net) or hostname.
  if (/_allowed$|_blocked$/.test(event.type)) {
    const target = d.target || d.hostname ||
      (d.dst_ip && d.dst_port ? `${d.dst_ip}:${d.dst_port}` : '');
    return [target, d.reason].filter(Boolean).join(' · ');
  }
  return '';
}

export default function KernelPanel({ events }) {


  const [showAll, setShowAll] = useState(false);
  const CARD_LIMIT = 6;
  const displayed  = showAll ? events : events.slice(-CARD_LIMIT);
  const hiddenCount = events.length - CARD_LIMIT;

  return (
    <section className="panel">
      <header className="panel__header">
        <span className="panel__title">
          <span className="panel__badge panel__badge--kernel">KERNEL</span>
          Network events
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {!showAll && hiddenCount > 0 && (
            <button className="panel__showall" onClick={() => setShowAll(true)}>
              +{hiddenCount} more
            </button>
          )}
          {showAll && (
            <button className="panel__showall" onClick={() => setShowAll(false)}>
              collapse
            </button>
          )}
          <span className="panel__count">{events.length}</span>
        </div>
      </header>
      <div className="panel__feed">
        {events.length === 0 ? (
          <div className="panel__empty">waiting for kernel events…</div>
        ) : (
          displayed.map((event, i) => {
            const isNewest = i === displayed.length - 1;
            const label    = getLabel(event);
            const detail   = getDetail(event);
            const cls =
              `event-card type-${event.type}` +
              (isNewest ? ' event-card--newest' : '');
            return (
              <div key={event._id} className={cls}>
                <div className="event-card__top">
                  <span className="event-card__label">{label}</span>
                  <span className="event-card__time">{formatTime(event.ts)}</span>
                </div>
                {detail && <div className="event-card__detail">{detail}</div>}
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
