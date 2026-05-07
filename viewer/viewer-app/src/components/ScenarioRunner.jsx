import { useEffect, useState } from 'react';
import './ScenarioRunner.css';

// Polls /api/scenarios on mount, then renders one row per scenario:
//   [ ▶ run | scenario-name | (▾ show permissions) ]
// Clicking the ▶ button POSTs to /api/scenarios/run; clicking the chevron
// expands the permissions panel built from the parsed manifest.
export default function ScenarioRunner() {
  // status: 'loading' | 'ok' | 'error'
  // entries: [{ name, permissions?, parse_error? }]
  const [state, setState] = useState({ status: 'loading', entries: [], enabled: true });
  const [results, setResults] = useState({});
  const [expanded, setExpanded] = useState(() => new Set());

  useEffect(() => {
    let cancelled = false;
    fetch('/api/scenarios')
      .then(async (r) => {
        if (!r.ok) throw new Error(`scenario list HTTP ${r.status}`);
        return r.json();
      })
      .then((body) => {
        if (cancelled) return;
        const list = Array.isArray(body.scenarios) ? body.scenarios : [];
        // Backwards-compat: some older relay versions returned plain strings.
        const entries = list.map((x) => typeof x === 'string' ? { name: x } : x);
        setState({ status: 'ok', entries, enabled: body.enabled !== false });
      })
      .catch((err) => {
        if (cancelled) return;
        setState({ status: 'error', entries: [], enabled: false, message: err.message });
      });
    return () => { cancelled = true; };
  }, []);

  const runOne = async (name) => {
    setResults((prev) => ({ ...prev, [name]: 'running' }));
    try {
      const r = await fetch('/api/scenarios/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        setResults((prev) => ({ ...prev, [name]: { ok: false, message: body.message || `HTTP ${r.status}` } }));
        return;
      }
      setResults((prev) => ({
        ...prev,
        [name]: {
          ok: !!body.ok,
          message: body.ok
            ? `exit ${body.exit_code}`
            : (body.stderr ? body.stderr.split('\n')[0] : `exit ${body.exit_code}`),
        },
      }));
    } catch (err) {
      setResults((prev) => ({ ...prev, [name]: { ok: false, message: err.message } }));
    }
  };

  const toggle = (name) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  };

  if (state.status === 'loading') {
    return <div className="scenario-runner scenario-runner--muted">loading scenarios…</div>;
  }
  if (state.status === 'error') {
    return (
      <div className="scenario-runner scenario-runner--muted">
        scenario API unreachable: {state.message}
      </div>
    );
  }
  if (!state.enabled) {
    return <div className="scenario-runner scenario-runner--muted">scenario runner disabled by deployment</div>;
  }
  if (state.entries.length === 0) {
    return <div className="scenario-runner scenario-runner--muted">no scenarios installed under /examples/playground</div>;
  }

  return (
    <div className="scenario-runner">
      <div className="scenario-runner__label">demo scenarios</div>
      <ul className="scenario-runner__list">
        {state.entries.map((entry) => {
          const { name, permissions, parse_error } = entry;
          const r = results[name];
          const running = r === 'running';
          const lastOk = r && r !== 'running' ? r.ok : null;
          const isExpanded = expanded.has(name);
          return (
            <li key={name} className={`scenario-runner__item${isExpanded ? ' is-expanded' : ''}`}>
              <div className="scenario-runner__row">
                <button
                  type="button"
                  className={
                    'scenario-runner__run' +
                    (running ? ' is-running' : '') +
                    (lastOk === true ? ' is-ok' : '') +
                    (lastOk === false ? ' is-fail' : '')
                  }
                  disabled={running}
                  onClick={() => runOne(name)}
                  title={
                    r && r !== 'running'
                      ? `last run: ${r.ok ? 'ok' : 'fail'} — ${r.message || ''}`
                      : `run ${name}`
                  }
                >
                  {running ? '…' : lastOk === true ? '✓' : lastOk === false ? '✗' : '▶'}
                </button>
                <span className="scenario-runner__name">{name}</span>
                {permissions && (
                  <span className={`scenario-runner__mode mode-${permissions.mode}`}>
                    {permissions.mode}
                  </span>
                )}
                <button
                  type="button"
                  className="scenario-runner__toggle"
                  onClick={() => toggle(name)}
                  aria-expanded={isExpanded}
                  aria-label={isExpanded ? 'hide permissions' : 'show permissions'}
                  title={isExpanded ? 'hide permissions' : 'show permissions'}
                >
                  {isExpanded ? '▾' : '▸'} permissions
                </button>
              </div>
              {isExpanded && (
                <PermissionsCard permissions={permissions} parseError={parse_error} />
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// Renders the parsed manifest summary as four pillar rows. Each row shows:
//   - A pillar chip (NET / FILE / EXEC / CRED)
//   - A one-line plain-English summary of what's allowed/blocked
//   - The literal allow-list entries, monospaced, so an operator can verify
//     against the manifest text.
function PermissionsCard({ permissions, parseError }) {
  if (parseError) {
    return (
      <div className="permissions permissions--error">
        could not parse this manifest: {parseError}
      </div>
    );
  }
  if (!permissions) {
    return <div className="permissions permissions--muted">no permissions data</div>;
  }
  return (
    <div className="permissions">
      {permissions.description && (
        <p className="permissions__desc">{permissions.description}</p>
      )}
      <div className="permissions__grid">
        {permissions.pillars.map((p) => (
          <div key={p.id} className={`permissions__pillar tone-${p.tone}`}>
            <div className="permissions__pillar-head">
              <span className={`permissions__chip pillar-${p.id}`}>
                {pillarShort(p.id)}
              </span>
              <span className="permissions__pillar-label">{p.label}</span>
            </div>
            <p className="permissions__pillar-summary">{p.summary}</p>
            <PillarEntries id={p.id} allowed={p.allowed} forbidden={p.forbidden} />
          </div>
        ))}
      </div>
    </div>
  );
}

function PillarEntries({ id, allowed, forbidden }) {
  // For credentials we render the forbidden_caps list; for other pillars
  // we render the allow-list. An empty allow-list is meaningful (the
  // summary line above already explains it), so we skip rendering chips.
  const items = id === 'credentials' ? (forbidden || []) : (allowed || []);
  if (!items || items.length === 0) return null;
  const verb = id === 'credentials' ? 'forbidden' : 'allowed';
  return (
    <ul className={`permissions__entries entries-${verb}`}>
      {items.map((item) => (
        <li key={item}><code>{item}</code></li>
      ))}
    </ul>
  );
}

function pillarShort(id) {
  switch (id) {
    case 'network':     return 'NET';
    case 'filesystem':  return 'FILE';
    case 'exec':        return 'EXEC';
    case 'credentials': return 'CRED';
    default: return id.toUpperCase();
  }
}
