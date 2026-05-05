import { useEffect, useRef } from 'react';
import './Panel.css';
import './EventRow.css';
import AlertBanner from './AlertBanner.jsx';

function formatTime(ts) {
  if (!ts && ts !== 0) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false }) + '.' +
    String(d.getMilliseconds()).padStart(3, '0');
}

function trunc(str, n) {
  if (!str) return '';
  const s = String(str);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function getLabel(event) {
  const data = event.data || {};
  switch (event.type) {
    case 'session_start': return 'Session initialised';
    case 'user_input':    return 'Task received';
    case 'tool_call':     return 'Agent fetched a URL';
    case 'tool_result':   return data.ok ? 'Fetch succeeded' : 'Fetch failed';
    case 'agent_output':  return 'Agent responded';
    case 'stdout':        return (data.line ?? '').trim() === '' ? null : 'Agent log';
    case 'stopped':       return 'Session completed';
    case 'crashed':       return 'Session crashed';
    default:              return event.type;
  }
}

function getDetail(event) {
  const data = event.data || {};
  switch (event.type) {
    case 'session_start': {
      const pid  = data.pid        ? `pid ${data.pid}`        : '';
      const mode = data.launch_mode ? `${data.launch_mode} mode` : '';
      return [pid, mode].filter(Boolean).join(' · ');
    }
    case 'user_input':   return trunc(data.text, 60);
    case 'tool_call': {
      const url = data.args?.url || Object.values(data.args || {})[0] || '';
      return `${data.tool || 'tool'} → ${url}`;
    }
    case 'tool_result': {
      const parts = [data.url, data.status_code, data.chars != null ? `${data.chars} chars` : null];
      return parts.filter(Boolean).join(' · ');
    }
    case 'agent_output': return trunc(data.text, 60);
    case 'stdout':       return trunc(data.line, 60);
    case 'stopped':      return `exit ${data.exit_code ?? 0}`;
    case 'crashed':      return `exit ${data.exit_code ?? '?'}`;
    default:             return '';
  }
}

export default function LLMPanel({ events, alert, injectionTargets, onDismissAlert }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ block: 'end' });
    }
  }, [events.length]);

  const targets = injectionTargets || null;

  // Skip stdout rows that are empty
  const visible = events.filter((e) => {
    if (e.type === 'stdout' && (e.data?.line ?? '').trim() === '') return false;
    return true;
  });

  return (
    <section className="panel">
      <header className="panel__header">
        <span className="panel__title">
          <span className="panel__badge panel__badge--llm">LLM</span>
          Agent events
        </span>
        <span className="panel__count">{visible.length}</span>
      </header>
      {alert && (
        <AlertBanner
          key={alert.kernelId}
          hostname={alert.hostname}
          reason={alert.reason}
          onDismiss={onDismissAlert}
        />
      )}
      <div className="panel__feed">
        {visible.length === 0 ? (
          <div className="panel__empty">waiting for LLM events…</div>
        ) : (
          visible.map((event) => {
            const isTarget = targets && targets.has(event._id);
            const label  = getLabel(event);
            const detail = getDetail(event);
            const cls =
              `event-row event-row--two-line type-${event.type}` +
              (isTarget ? ' is-injection-target' : '');
            return (
              <div key={event._id} className={cls}>
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
