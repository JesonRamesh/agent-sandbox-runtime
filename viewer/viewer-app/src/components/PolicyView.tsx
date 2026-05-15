import { useCallback, useEffect, useState } from 'react';
import { createBinding, createPolicy, fetchPolicies, updatePolicy } from '../api/daemonApi';
import type { Policy } from '../api/daemonApi';
import { MOCK_POLICIES } from '../api/mockPolicies';
import BindingsForm from './BindingsForm';
import PolicyCard from './PolicyCard';
import PolicyDialog from './PolicyDialog';
import DaemonHealth from './DaemonHealth';
import './PolicyView.css';

interface PolicyViewProps {
  onCountChange?: (n: number) => void;
}

export default function PolicyView({ onCountChange }: PolicyViewProps) {
  const [policies, setPolicies]         = useState<Policy[]>([]);
  const [loading, setLoading]           = useState(true);
  const [fetchError, setFetchError]     = useState<string | null>(null);
  const [usingMock, setUsingMock]       = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);  // null = closed
  const [showDialog, setShowDialog]     = useState(false);
  const [search, setSearch]             = useState('');

  // ── Load policies from daemon ──────────────────────────────────────────
  const load = useCallback(async () => {
    setLoading(true);
    setFetchError(null);
    setUsingMock(false);
    try {
      const data = await fetchPolicies();
      const sorted = (data || []).sort((a, b) => a.id - b.id);
      setPolicies(sorted);
      onCountChange?.(sorted.length);
    } catch (err) {
      // Daemon unreachable — fall back to mock data so the UI is always demo-able
      setFetchError(err instanceof Error ? err.message : String(err));
      setPolicies(MOCK_POLICIES);
      setUsingMock(true);
      onCountChange?.(MOCK_POLICIES.length);
    } finally {
      setLoading(false);
    }
  }, [onCountChange]);

  useEffect(() => { load(); }, [load]);

  // ── Dialog handlers ───────────────────────────────────────────────────
  function openNew() {
    setEditingPolicy(null);
    setShowDialog(true);
  }

  function openEdit(policy: Policy) {
    setEditingPolicy(policy);
    setShowDialog(true);
  }

  function closeDialog() {
    setShowDialog(false);
    setEditingPolicy(null);
  }

  async function handleSave(payload: Policy, isNew: boolean) {
    if (usingMock) {
      // Daemon offline — apply edits locally to mock data so demo still works
      setPolicies((prev) => {
        const without = prev.filter((p) => p.id !== payload.id);
        const next = [...without, payload].sort((a, b) => a.id - b.id);
        onCountChange?.(next.length);
        return next;
      });
      return;
    }
    if (isNew) {
      await createPolicy(payload);
    } else {
      await updatePolicy(payload.id, payload);
    }
    await load();
  }

  // ── Bindings handler ──────────────────────────────────────────────────
  async function handleBind(cgroupId: number, policyId: number) {
    await createBinding(cgroupId, policyId);
  }

  // ── Filtered policy list ──────────────────────────────────────────────
  const filtered = policies.filter((p) => {
    if (!search.trim()) return true;
    const q = search.trim().toLowerCase();
    return (
      String(p.id).includes(q) ||
      (p.name || '').toLowerCase().includes(q) ||
      (p.mode || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="policy-view">

      {/* ── Toolbar ─────────────────────────────────────────────────── */}
      <div className="policy-view__toolbar">
        <div className="policy-view__toolbar-left">
          <span className="policy-view__heading">Policies</span>
          {!loading && (
            <span className="policy-view__count">
              {filtered.length} / {policies.length}
            </span>
          )}
        </div>
        <div className="policy-view__toolbar-right">
          <DaemonHealth />
          <input
            className="policy-view__search"
            type="text"
            placeholder="Search by id, name, mode…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button className="policy-view__new-btn" onClick={openNew}>
            + New policy
          </button>
          <button className="policy-view__refresh-btn" onClick={load} disabled={loading} title="Refresh">
            ↺
          </button>
        </div>
      </div>

      {/* ── Error / mock-mode banner ──────────────────────────────────── */}
      {fetchError && (
        <div className={`policy-view__error ${usingMock ? 'policy-view__error--mock' : ''}`}>
          <span className="policy-view__error-icon">{usingMock ? '⚡' : '⚠'}</span>
          <span>
            {usingMock ? (
              <>Daemon offline — showing <strong>mock data</strong>. Edits are local only.{' '}
              Start <code>agentd</code> on port 9000 and retry to go live.</>
            ) : (
              <>Could not reach daemon — <code>{fetchError}</code>. Make sure{' '}
              <code>agentd</code> is running on port 9000.</>
            )}
          </span>
          <button className="policy-view__retry" onClick={load}>Retry</button>
        </div>
      )}

      {/* ── Loading skeleton ─────────────────────────────────────────── */}
      {loading && !fetchError && (
        <div className="policy-view__grid">
          {[1, 2, 3].map((i) => (
            <div key={i} className="policy-view__skeleton" />
          ))}
        </div>
      )}

      {/* ── Empty state ──────────────────────────────────────────────── */}
      {!loading && !fetchError && filtered.length === 0 && (
        <div className="policy-view__empty">
          {search ? (
            <>
              <span className="policy-view__empty-icon">🔍</span>
              <span>No policies match <em>"{search}"</em></span>
            </>
          ) : (
            <>
              <span className="policy-view__empty-icon">🛡</span>
              <span>No policies yet — create one to get started.</span>
            </>
          )}
        </div>
      )}

      {/* ── Policy grid ──────────────────────────────────────────────── */}
      {!loading && filtered.length > 0 && (
        <div className="policy-view__grid">
          {filtered.map((p) => (
            <PolicyCard key={p.id} policy={p} onEdit={openEdit} />
          ))}
        </div>
      )}

      {/* ── Bindings section ─────────────────────────────────────────── */}
      {!loading && !fetchError && (
        <BindingsForm onBind={handleBind} />
      )}

      {/* ── Create / edit dialog ─────────────────────────────────────── */}
      {showDialog && (
        <PolicyDialog
          policy={editingPolicy}
          onSave={handleSave}
          onClose={closeDialog}
        />
      )}

    </div>
  );
}