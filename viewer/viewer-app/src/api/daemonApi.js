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