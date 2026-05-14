// =============================================================================
// Agent Sandbox — daemon → viewer event schema transform.
//
// The daemon's wire schema is documented in docs/INTERFACES.md §4 and is the
// canonical shape any consumer of the IPC + WebSocket APIs must accept. The
// browser viewer uses a *different*, narrower shape (see viewer-app/src/App.jsx
// and KernelPanel.jsx): numeric epoch-second timestamps, a flat `agent`
// display label rather than `agent_id`, payload under `data` rather than
// `details`, a `pillar` field naming the policy domain, and a small fixed set
// of `type` strings (one per pillar × verdict).
//
// Translating between the two is the bridge's job. This module is pure (no
// I/O, no side effects) so it can be unit-tested without standing up a
// daemon. The single mutable input — the agent_id → friendly name map — is
// passed in by the caller, which lets tests assert on its contents.
// =============================================================================

'use strict';

// Stable wire `type` constants for the canonical (daemon) schema.
const KIND_NET_CONNECT   = 'net.connect';
const KIND_NET_SENDTO    = 'net.sendto';
const KIND_FILE_OPEN     = 'file.open';
const KIND_EXEC          = 'exec';
const KIND_EXEC_BPRM     = 'exec.bprm';
const KIND_CREDS_SETUID  = 'creds.setuid';
const KIND_CREDS_SETGID  = 'creds.setgid';
const KIND_CREDS_CAPSET  = 'creds.capset';
const KIND_AGENT_STARTED = 'agent.started';
const KIND_AGENT_EXITED  = 'agent.exited';
const KIND_AGENT_CRASHED = 'agent.crashed';

// UI-side types accepted by viewer-app/src/App.jsx. One pair per pillar so
// the dashboard can show separate counters and badges, plus the lifecycle
// types pulled in by LLM_TYPES.
const UI = Object.freeze({
  NET_ALLOWED:   'net_allowed',
  NET_BLOCKED:   'net_blocked',
  FILE_ALLOWED:  'file_allowed',
  FILE_BLOCKED:  'file_blocked',
  EXEC_ALLOWED:  'exec_allowed',
  EXEC_BLOCKED:  'exec_blocked',
  CRED_ALLOWED:  'cred_allowed',
  CRED_BLOCKED:  'cred_blocked',
  STOPPED:       'stopped',
  CRASHED:       'crashed',
});

// Known UI kernel types as a flat set (mirrors KERNEL_TYPES in App.jsx —
// keep in sync). Exported so tests and other consumers can introspect.
const UI_KERNEL_TYPES = new Set([
  UI.NET_ALLOWED, UI.NET_BLOCKED,
  UI.FILE_ALLOWED, UI.FILE_BLOCKED,
  UI.EXEC_ALLOWED, UI.EXEC_BLOCKED,
  UI.CRED_ALLOWED, UI.CRED_BLOCKED,
]);

// Convert an ISO-8601 timestamp (what the daemon emits, RFC 3339 nanos) to
// the float-seconds-since-epoch the UI's date arithmetic expects.
// Returns 0 on parse failure rather than NaN — NaN propagates through the
// `Math.abs(blocked.ts - e.ts)` window comparison and silently mismatches.
function isoToEpochSeconds(iso) {
  if (typeof iso !== 'string') return 0;
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return 0;
  return ms / 1000;
}

// Pick a friendly display label for an agent given the bridge's running
// id→name registry. Falls back to a 12-char prefix of the opaque id so the
// agent strip is at least readable when the bridge missed `agent.started`
// (e.g. it reconnected after the agent already started).
function agentLabel(agentId, names) {
  if (!agentId) return 'unknown';
  const friendly = names.get(agentId);
  if (friendly) return friendly;
  return agentId.length > 12 ? agentId.slice(0, 12) : agentId;
}

// Map (kind → pillar). Mirrors policy.Pillar in internal/policy/attribute.go;
// keep them in sync.
function pillarOf(kind) {
  switch (kind) {
    case KIND_NET_CONNECT:
    case KIND_NET_SENDTO:
      return 'net';
    case KIND_FILE_OPEN:
      return 'file';
    case KIND_EXEC:
    case KIND_EXEC_BPRM:
      return 'exec';
    case KIND_CREDS_SETUID:
    case KIND_CREDS_SETGID:
    case KIND_CREDS_CAPSET:
      return 'cred';
    default:
      return 'unknown';
  }
}

// Compose the UI type from pillar + verdict. `audit` is treated as allowed
// because the call did *not* fail at the syscall boundary; a separate UX
// would be needed to call out observe-only mode.
function uiTypeFor(pillar, verdict) {
  const blocked = verdict === 'deny';
  switch (pillar) {
    case 'net':  return blocked ? UI.NET_BLOCKED  : UI.NET_ALLOWED;
    case 'file': return blocked ? UI.FILE_BLOCKED : UI.FILE_ALLOWED;
    case 'exec': return blocked ? UI.EXEC_BLOCKED : UI.EXEC_ALLOWED;
    case 'cred': return blocked ? UI.CRED_BLOCKED : UI.CRED_ALLOWED;
    default:     return blocked ? UI.NET_BLOCKED  : UI.NET_ALLOWED; // safest UI fallback
  }
}

// Build the `data` payload for a translated kernel event. Fields the UI
// reads (KernelPanel.renderContent / EventDetail):
//   - data.pillar         : "net" | "file" | "exec" | "cred"
//   - data.kind           : raw daemon kind, e.g. "net.connect"
//   - data.target         : short human label ("8.8.8.8:53", "/etc/shadow", "/usr/bin/curl")
//   - data.dst_ip / port  : present only for net events (legacy renderer)
//   - data.hostname       : alias of target so the older renderer keeps working
//   - data.reason         : daemon-attributed reason_message (preferred), else fallback
//   - data.reason_code    : machine-comparable code from the daemon (optional)
//   - data.matched_rule   : entry from the manifest that allowed the call (optional)
//   - data.comm           : process name at syscall time
//   - data.pid            : pid at syscall time (forwarded by caller)
function buildKernelData(kind, details) {
  const pillar = pillarOf(kind);
  const verdict = details.verdict || 'unknown';
  const comm = details.comm || '';

  // Common fields every kernel row gets; pillar-specific code below adds
  // target/hostname or extra fields and may overwrite defaults.
  const data = {
    pillar,
    kind,
    verdict,
    comm,
    reason_code: details.reason_code || '',
    reason: details.reason_message || `${kind} ${verdict}`,
  };
  if (details.matched_rule) data.matched_rule = details.matched_rule;

  switch (kind) {
    case KIND_NET_CONNECT:
    case KIND_NET_SENDTO: {
      const ip = details.daddr || '';
      const port = details.dport || 0;
      const target = port ? `${ip}:${port}` : ip;
      data.dst_ip = ip;
      data.dst_port = port;
      data.target = target;
      data.hostname = target;
      break;
    }
    case KIND_FILE_OPEN: {
      const path = details.path || '';
      data.path = path;
      data.target = path;
      data.hostname = path;
      break;
    }
    case KIND_EXEC:
    case KIND_EXEC_BPRM: {
      const filename = details.filename || '';
      data.filename = filename;
      data.target = filename;
      data.hostname = filename;
      break;
    }
    case KIND_CREDS_SETUID:
    case KIND_CREDS_SETGID: {
      const oldId = details.old_id ?? '?';
      const newId = details.new_id ?? '?';
      const target = `${kind}: ${oldId}→${newId}`;
      data.old_id = oldId;
      data.new_id = newId;
      data.target = target;
      data.hostname = target;
      break;
    }
    case KIND_CREDS_CAPSET: {
      const cap = details.cap_effective;
      const capStr = typeof cap === 'number' ? `0x${cap.toString(16)}` : String(cap ?? '?');
      const target = `capset: cap_eff=${capStr}`;
      data.cap_effective = cap;
      data.target = target;
      data.hostname = target;
      break;
    }
    default: {
      const target = `kernel:${kind}`;
      data.target = target;
      data.hostname = target;
    }
  }
  return data;
}

// Translate one daemon event into the UI schema. Returns:
//   - a UI event object to forward, OR
//   - null if the event should be dropped (lifecycle events the UI doesn't
//     model, malformed input, etc.)
//
// `names` is a Map<agent_id, friendly_name>; the bridge owns it across calls
// and this function may add to it when it observes `agent.started` events.
function transformDaemonEvent(raw, names) {
  if (!raw || typeof raw !== 'object') return null;
  if (typeof raw.type !== 'string') return null;
  if (typeof raw.agent_id !== 'string') return null;

  const details = (raw.details && typeof raw.details === 'object') ? raw.details : {};
  const ts = isoToEpochSeconds(raw.ts);

  // Lifecycle: agent.started carries the manifest name. Record it for future
  // events on the same agent_id; never forward to the UI (it has no type for
  // it, and the agent will be visible the moment its first kernel event
  // arrives).
  if (raw.type === KIND_AGENT_STARTED) {
    if (typeof details.name === 'string' && details.name.length > 0) {
      names.set(raw.agent_id, details.name);
    }
    return null;
  }

  if (raw.type === KIND_AGENT_EXITED || raw.type === KIND_AGENT_CRASHED) {
    return {
      ts,
      agent: agentLabel(raw.agent_id, names),
      type: raw.type === KIND_AGENT_EXITED ? UI.STOPPED : UI.CRASHED,
      data: {
        exit_code: details.exit_code,
        reason: details.reason || (raw.type === KIND_AGENT_EXITED ? 'exited' : 'crashed'),
      },
    };
  }

  // Anything not lifecycle and not a known kernel kind: drop. This explicitly
  // covers `llm.*` orchestrator events, which arrive on a different sender
  // (P4 orchestrator), not through this bridge — but if someone wires the
  // daemon to relay them, we'd rather drop than mis-label.
  const isKernel = (
    raw.type === KIND_NET_CONNECT ||
    raw.type === KIND_NET_SENDTO ||
    raw.type === KIND_FILE_OPEN ||
    raw.type === KIND_EXEC ||
    raw.type === KIND_EXEC_BPRM ||
    raw.type === KIND_CREDS_SETUID ||
    raw.type === KIND_CREDS_SETGID ||
    raw.type === KIND_CREDS_CAPSET
  );
  if (!isKernel) return null;

  const data = buildKernelData(raw.type, details);
  if (typeof raw.pid === 'number') data.pid = raw.pid;

  return {
    ts,
    agent: agentLabel(raw.agent_id, names),
    type: uiTypeFor(data.pillar, details.verdict),
    data,
  };
}

module.exports = {
  transformDaemonEvent,
  // Exported for tests + introspection.
  isoToEpochSeconds,
  agentLabel,
  buildKernelData,
  pillarOf,
  uiTypeFor,
  UI_KERNEL_TYPES,
  UI,
};
