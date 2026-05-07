import { useEffect, useRef, useState } from 'react';
import './PolicyDialog.css';

const EMPTY = {
  id: '',
  name: '',
  mode: 'audit',
  allowed_hosts: [],
  allowed_paths: [],
  allowed_bins: [],
  forbidden_caps: [],
};

function lines(arr) {
  return (arr || []).join('\n');
}

function parseLines(str) {
  return str.split('\n').map((s) => s.trim()).filter(Boolean);
}

export default function PolicyDialog({ policy, onSave, onClose }) {
  const dialogRef = useRef(null);
  const isNew = !policy?.id;

  const [form, setForm] = useState(() => ({
    id:             policy?.id             ?? '',
    name:           policy?.name           ?? '',
    mode:           policy?.mode           ?? 'audit',
    allowed_hosts:  lines(policy?.allowed_hosts),
    allowed_paths:  lines(policy?.allowed_paths),
    allowed_bins:   lines(policy?.allowed_bins),
    forbidden_caps: lines(policy?.forbidden_caps),
  }));

  const [error, setError]     = useState(null);
  const [saving, setSaving]   = useState(false);

  // Open the native <dialog> on mount
  useEffect(() => {
    dialogRef.current?.showModal();
  }, []);

  // Close on backdrop click
  function handleDialogClick(e) {
    const rect = dialogRef.current.getBoundingClientRect();
    const outside =
      e.clientX < rect.left || e.clientX > rect.right ||
      e.clientY < rect.top  || e.clientY > rect.bottom;
    if (outside) handleClose();
  }

  function handleClose() {
    dialogRef.current?.close();
    onClose();
  }

  function set(field) {
    return (e) => setForm((f) => ({ ...f, [field]: e.target.value }));
  }

  async function handleSave(e) {
    e.preventDefault();
    setError(null);

    const id = Number(form.id);
    if (!id || id < 1) {
      setError('Policy ID must be a number greater than 0.');
      return;
    }

    const payload = {
      id,
      name:           form.name.trim(),
      mode:           form.mode,
      allowed_hosts:  parseLines(form.allowed_hosts),
      allowed_paths:  parseLines(form.allowed_paths),
      allowed_bins:   parseLines(form.allowed_bins),
      forbidden_caps: parseLines(form.forbidden_caps),
    };

    setSaving(true);
    try {
      await onSave(payload, isNew);
      handleClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <dialog ref={dialogRef} className="pd" onClick={handleDialogClick}>
      <form onSubmit={handleSave} onClick={(e) => e.stopPropagation()}>

        <div className="pd__header">
          <span className="pd__title">{isNew ? 'New policy' : `Edit policy #${policy.id}`}</span>
          <button type="button" className="pd__close" onClick={handleClose} aria-label="Close">✕</button>
        </div>

        {error && <div className="pd__error">{error}</div>}

        {/* Row: ID + Name */}
        <div className="pd__row">
          <label className="pd__label">
            ID
            <input
              className="pd__input"
              type="number"
              min="1"
              required
              disabled={!isNew}
              value={form.id}
              onChange={set('id')}
              placeholder="e.g. 1"
            />
          </label>
          <label className="pd__label pd__label--grow">
            Name
            <input
              className="pd__input"
              type="text"
              required
              value={form.name}
              onChange={set('name')}
              placeholder="e.g. llm-agent-policy"
            />
          </label>
        </div>

        {/* Mode */}
        <label className="pd__label">
          Mode
          <select className="pd__select" value={form.mode} onChange={set('mode')}>
            <option value="audit">audit — observe only, no blocking</option>
            <option value="enforce">enforce — kernel-level deny</option>
          </select>
        </label>

        {/* Allowed hosts */}
        <label className="pd__label">
          Allowed hosts
          <span className="pd__hint">one per line · host:port, IP, or CIDR</span>
          <textarea
            className="pd__textarea"
            rows={4}
            value={form.allowed_hosts}
            onChange={set('allowed_hosts')}
            placeholder={`example.com:443\n93.184.216.34\n10.0.0.0/8`}
          />
        </label>

        {/* Allowed paths */}
        <label className="pd__label">
          Allowed paths
          <span className="pd__hint">prefix match · one per line</span>
          <textarea
            className="pd__textarea"
            rows={3}
            value={form.allowed_paths}
            onChange={set('allowed_paths')}
            placeholder="/tmp/agent\n/usr/bin"
          />
        </label>

        {/* Allowed binaries */}
        <label className="pd__label">
          Allowed binaries
          <span className="pd__hint">exact path · one per line</span>
          <textarea
            className="pd__textarea"
            rows={2}
            value={form.allowed_bins}
            onChange={set('allowed_bins')}
            placeholder="/usr/bin/python3\n/usr/bin/curl"
          />
        </label>

        {/* Forbidden caps */}
        <label className="pd__label">
          Forbidden capabilities
          <span className="pd__hint">e.g. CAP_SYS_ADMIN · one per line</span>
          <textarea
            className="pd__textarea"
            rows={2}
            value={form.forbidden_caps}
            onChange={set('forbidden_caps')}
            placeholder="CAP_SYS_ADMIN\nCAP_NET_RAW"
          />
        </label>

        <div className="pd__actions">
          <button type="button" className="pd__btn pd__btn--cancel" onClick={handleClose}>
            Cancel
          </button>
          <button type="submit" className="pd__btn pd__btn--save" disabled={saving}>
            {saving ? 'Saving…' : isNew ? 'Create policy' : 'Save changes'}
          </button>
        </div>

      </form>
    </dialog>
  );
}