import { useCallback, useEffect, useState } from 'react';
import { createBinding, createPolicy, fetchPolicies, updatePolicy } from '../api/daemonApi.js';
import BindingsForm from './BindingsForm.jsx';
import PolicyCard from './PolicyCard.jsx';
import PolicyDialog from './PolicyDialog.jsx';
import './PolicyView.css';

export default function PolicyView() {
  const [policies, setPolicies]         = useState([]);
  const [loading, setLoading]           = useState(true);
  const [fetchError, setFetchError]     = useState(null);
  const [editingPolicy, setEditingPolicy] = useState(null);  // null = closed
  const [showDialog, setShowDialog]     = useState(false);
  const [search, setSearch]             = useState('');

  // ── Load policies from daemon ──────────────────────────────────────────
  const load = useCallback(async () => {
    setLoading(true);
    setFetchError(null);
    try {
      const data = await fetchPolicies();
      // Sort by id for stable ordering
      setPolicies((data || []).sort((a, b) => a.id - b.id));
    } catch (err) {
      setFetchError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // ── Dialog handlers ───────────────────────────────────────────────────
  function openNew() {
    setEditingPolicy(null);
    setShowDialog(true);
  }

  function openEdit(policy) {
    setEditingPolicy(policy);
    setShowDialog(true);
  }

  function closeDialog() {
    setShowDialog(false);
    setEditingPolicy(null);
  }

  async function handleSave(payload, isNew) {
    if (isNew) {
      await createPolicy(payload);
    } else {
      await updatePolicy(payload.id, payload);
    }
    await load();
  }

  // ── Bindings handler ──────────────────────────────────────────────────
  async function handleBind(cgroupId, policyId) {
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

      {/* ── Error state ──────────────────────────────────────────────── */}
      {fetchError && (
        <div className="policy-view__error">
          <span className="policy-view__error-icon">⚠</span>
          <span>
            Could not reach daemon — <code>{fetchError}</code>. Make sure{' '}
            <code>agentd</code> is running on port 9000.
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