import { useState } from 'react';
import './BindingsForm.css';

export default function BindingsForm({ onBind }) {
  const [cgroupId, setCgroupId] = useState('');
  const [policyId, setPolicyId] = useState('');
  const [status, setStatus]     = useState(null); // { ok: bool, msg: string }
  const [saving, setSaving]     = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setStatus(null);
    setSaving(true);
    try {
      await onBind(Number(cgroupId), Number(policyId));
      const msg = Number(policyId) === 0
        ? `Cgroup ${cgroupId} unbound — now unmanaged.`
        : `Cgroup ${cgroupId} bound to policy #${policyId}.`;
      setStatus({ ok: true, msg });
      setCgroupId('');
      setPolicyId('');
    } catch (err) {
      setStatus({ ok: false, msg: err.message });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="bindings">
      <div className="bindings__header">
        <span className="bindings__title">
          <span className="bindings__badge">BINDINGS</span>
          Cgroup → Policy
        </span>
      </div>

      <p className="bindings__desc">
        Bind a Linux cgroup to a policy to apply its rules kernel-side. Find a
        cgroup ID with{' '}
        <code className="bindings__code">stat -c %i /sys/fs/cgroup/&lt;path&gt;</code>{' '}
        or from the <em>cgroup_id</em> column in the Events view.
        Set policy ID to <code className="bindings__code">0</code> to unbind.
      </p>

      <form className="bindings__form" onSubmit={handleSubmit}>
        <label className="bindings__label">
          <span className="bindings__label-text">Cgroup ID</span>
          <input
            className="bindings__input"
            type="number"
            min="1"
            required
            value={cgroupId}
            onChange={(e) => setCgroupId(e.target.value)}
            placeholder="e.g. 1234"
          />
        </label>

        <label className="bindings__label">
          <span className="bindings__label-text">Policy ID</span>
          <input
            className="bindings__input"
            type="number"
            min="0"
            required
            value={policyId}
            onChange={(e) => setPolicyId(e.target.value)}
            placeholder="e.g. 1  (0 = unbind)"
          />
        </label>

        <button
          type="submit"
          className="bindings__btn"
          disabled={saving}
        >
          {saving ? 'Binding…' : 'Bind'}
        </button>
      </form>

      {status && (
        <div className={`bindings__status ${status.ok ? 'bindings__status--ok' : 'bindings__status--err'}`}>
          {status.ok ? '✓' : '✗'} {status.msg}
        </div>
      )}
    </div>
  );
}