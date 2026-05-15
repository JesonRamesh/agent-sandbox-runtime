// daemonApi.ts — thin fetch wrapper for the Go daemon's REST API
// (Mehul's daemon/internal/api/server.go endpoints)
//
// In dev, Vite proxies /api → http://localhost:9000 (see vite.config.ts).
// In production the daemon serves the built GUI from the same origin.

export interface Policy {
  id: number;
  name: string;
  mode: 'enforce' | 'audit' | string;
  allowed_hosts: string[];
  allowed_paths: string[];
  allowed_bins: string[];
  forbidden_caps: string[];
  deny_cleartext_egress?: boolean;
}

// runPolicy returns the binding row created by the daemon ({ id, cgroup_id,
// policy_id, ... }). Daemon may add fields freely; we accept any extras.
export interface RunPolicyResult {
  id?: number;
  cgroup_id?: number | string;
  policy_id?: number;
  [key: string]: unknown;
}

// runLlmAgent returns { ok, pid, started_at } plus any extras the
// orchestrator decides to surface.
export interface RunLlmAgentResult {
  ok: boolean;
  pid?: number;
  started_at?: string | number;
  [key: string]: unknown;
}

// ─── Policies ─────────────────────────────────────────────────────────────

export async function fetchPolicies(): Promise<Policy[]> {
  const res = await fetch('/api/policies');
  if (!res.ok) throw new Error(`fetchPolicies: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function createPolicy(policy: Policy): Promise<Policy> {
  const res = await fetch('/api/policies', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(policy),
  });
  if (!res.ok) throw new Error(`createPolicy: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function updatePolicy(id: number, policy: Policy): Promise<Policy> {
  const res = await fetch(`/api/policies/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...policy, id }),
  });
  if (!res.ok) throw new Error(`updatePolicy: ${res.status} ${res.statusText}`);
  return res.json();
}

// ─── Bindings ─────────────────────────────────────────────────────────────

export async function createBinding(cgroupId: number, policyId: number): Promise<void> {
  const res = await fetch('/api/bindings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cgroup_id: Number(cgroupId), policy_id: Number(policyId) }),
  });
  if (!res.ok) throw new Error(`createBinding: ${res.status} ${res.statusText}`);
  // 204 No Content on success
}

export async function runPolicy(policyId: number, label: string = 'demo'): Promise<RunPolicyResult> {
  const res = await fetch('/api/bindings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cgroup_id: String(label), policy_id: Number(policyId) }),
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const body = await res.json(); if (body && body.message) msg = body.message; } catch { /* ignore */ }
    throw new Error(`runPolicy: ${msg}`);
  }
  return res.json();
}

export async function runLlmAgent(task: string): Promise<RunLlmAgentResult> {
  const res = await fetch('/api/llm/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ task }),
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const body = await res.json(); if (body && body.message) msg = body.message; } catch { /* ignore */ }
    throw new Error(`runLlmAgent: ${msg}`);
  }
  return res.json();
}

// ─── Health ────────────────────────────────────────────────────────────────

export async function pingDaemon(): Promise<boolean> {
  try {
    const res = await fetch('/api/healthz');
    return res.ok;
  } catch {
    return false;
  }
}
