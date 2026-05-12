// daemonApi.js — thin fetch wrapper for the Go daemon's REST API
// (Mehul's daemon/internal/api/server.go endpoints)
//
// In dev, Vite proxies /api → http://localhost:9000 (see vite.config.js).
// In production the daemon serves the built GUI from the same origin.

// ─── Policies ─────────────────────────────────────────────────────────────

/**
 * Fetch all policies from the daemon.
 * @returns {Promise<Policy[]>}
 */
export async function fetchPolicies() {
  const res = await fetch('/api/policies');
  if (!res.ok) throw new Error(`fetchPolicies: ${res.status} ${res.statusText}`);
  return res.json();
}

/**
 * Create a new policy.
 * @param {Policy} policy  — must include id > 0
 * @returns {Promise<Policy>}
 */
export async function createPolicy(policy) {
  const res = await fetch('/api/policies', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(policy),
  });
  if (!res.ok) throw new Error(`createPolicy: ${res.status} ${res.statusText}`);
  return res.json();
}

/**
 * Update an existing policy by id.
 * @param {number} id
 * @param {Policy} policy
 * @returns {Promise<Policy>}
 */
export async function updatePolicy(id, policy) {
  const res = await fetch(`/api/policies/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...policy, id }),
  });
  if (!res.ok) throw new Error(`updatePolicy: ${res.status} ${res.statusText}`);
  return res.json();
}

// ─── Bindings ─────────────────────────────────────────────────────────────

/**
 * Bind a cgroup ID to a policy ID.
 * Setting policy_id = 0 removes the binding (cgroup becomes unmanaged).
 * @param {number} cgroupId
 * @param {number} policyId
 * @returns {Promise<void>}
 */
export async function createBinding(cgroupId, policyId) {
  const res = await fetch('/api/bindings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cgroup_id: Number(cgroupId), policy_id: Number(policyId) }),
  });
  if (!res.ok) throw new Error(`createBinding: ${res.status} ${res.statusText}`);
  // 204 No Content on success
}

/**
 * Apply a policy as a one-shot demo run. Behind the scenes this hits the
 * same /api/bindings endpoint as createBinding but accepts a free-form
 * `label` instead of a numeric cgroup id — the relay treats cgroup_id as
 * a display string and uses policy_id to look up which playground YAML to
 * spawn via agentctl.
 *
 * Returns the run result: { ok, exit_code, stdout, stderr, binding }.
 *
 * @param {number} policyId
 * @param {string} [label]   shown in the active-agents view, defaults to "demo"
 * @returns {Promise<object>}
 */
export async function runPolicy(policyId, label = 'demo') {
  const res = await fetch('/api/bindings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cgroup_id: String(label), policy_id: Number(policyId) }),
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const body = await res.json(); if (body && body.message) msg = body.message; } catch {}
    throw new Error(`runPolicy: ${msg}`);
  }
  return res.json();
}

/**
 * Fire the LLM-driven agent harness with a free-form task. The relay
 * spawns orchestrator/run_llm_agent.py and returns immediately (the
 * actual session_start / tool_call / agent_output events arrive over
 * the WebSocket as the LLM works).
 *
 * @param {string} task
 * @returns {Promise<{ok:boolean, pid:number, started_at:string}>}
 */
export async function runLlmAgent(task) {
  const res = await fetch('/api/llm/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ task }),
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const body = await res.json(); if (body && body.message) msg = body.message; } catch {}
    throw new Error(`runLlmAgent: ${msg}`);
  }
  return res.json();
}

// ─── Health ────────────────────────────────────────────────────────────────

/**
 * Ping the daemon. Resolves to true if reachable.
 * @returns {Promise<boolean>}
 */
export async function pingDaemon() {
  try {
    const res = await fetch('/api/healthz');
    return res.ok;
  } catch {
    return false;
  }
}