import { useState } from 'react';
import { runPolicy } from '../api/daemonApi';
import type { Policy, RunPolicyResult } from '../api/daemonApi';
import './PolicyCard.css';

const MODE_LABELS: Record<string, { label: string; cls: string }> = {
  enforce: { label: 'ENFORCE', cls: 'policy-card__mode--enforce' },
  audit:   { label: 'AUDIT',   cls: 'policy-card__mode--audit'   },
};

function RuleCount({ count, label }: { count: number; label: string }) {
  return (
    <div className="policy-card__rule">
      <span className="policy-card__rule-count">{count}</span>
      <span className="policy-card__rule-label">{label}</span>
    </div>
  );
}

type RunState = 'idle' | 'running' | { ok: boolean; message: string };

interface PolicyCardProps {
  policy: Policy;
  onEdit: (policy: Policy) => void;
  onRan?: (policy: Policy, result: RunPolicyResult) => void;
}

export default function PolicyCard({ policy, onEdit, onRan }: PolicyCardProps) {
  const mode = MODE_LABELS[policy.mode] || { label: policy.mode?.toUpperCase() || 'UNKNOWN', cls: '' };

  // Run-button state. `idle | running | { ok, message }` so a single render
  // can express all three. We don't bubble errors via toast — the dashboard
  // streams kernel events live, so the row colour + reason are the real
  // confirmation. The mark here is just a quick sanity indicator.
  const [runState, setRunState] = useState<RunState>('idle');

  async function handleRun() {
    setRunState('running');
    try {
      const result = await runPolicy(policy.id, `${policy.name}@dashboard`);
      const stderr = typeof result.stderr === 'string' ? result.stderr : '';
      setRunState({ ok: !!result.ok, message: result.ok ? `exit ${result.exit_code}` : stderr.split('\n')[0] });
      if (onRan) onRan(policy, result);
    } catch (err) {
      setRunState({ ok: false, message: err instanceof Error ? err.message : String(err) });
    }
    // Auto-reset to idle after 4s so a second click doesn't carry stale state.
    setTimeout(() => setRunState('idle'), 4000);
  }

  const running = runState === 'running';
  const lastOk  = runState && runState !== 'idle' && runState !== 'running' ? runState.ok : null;

  return (
    <div className="policy-card">
      <div className="policy-card__header">
        <div className="policy-card__title-row">
          <span className="policy-card__id">#{policy.id}</span>
          <span className="policy-card__name">{policy.name || '(unnamed)'}</span>
        </div>
        <span className={`policy-card__mode ${mode.cls}`}>{mode.label}</span>
      </div>

      <div className="policy-card__rules">
        <RuleCount count={(policy.allowed_hosts  || []).length} label="hosts"   />
        <RuleCount count={(policy.allowed_paths  || []).length} label="paths"   />
        <RuleCount count={(policy.allowed_bins   || []).length} label="binaries"/>
        <RuleCount count={(policy.forbidden_caps || []).length} label="caps"    />
      </div>

      {/* Preview allowed hosts if any */}
      {(policy.allowed_hosts || []).length > 0 && (
        <div className="policy-card__preview">
          {policy.allowed_hosts.slice(0, 3).map((h: string, i: number) => (
            <span key={i} className="policy-card__tag">{h}</span>
          ))}
          {policy.allowed_hosts.length > 3 && (
            <span className="policy-card__tag policy-card__tag--more">
              +{policy.allowed_hosts.length - 3} more
            </span>
          )}
        </div>
      )}

      <div className="policy-card__footer">
        <button
          type="button"
          className={
            'policy-card__run-btn' +
            (running ? ' is-running' : '') +
            (lastOk === true ? ' is-ok' : '') +
            (lastOk === false ? ' is-fail' : '')
          }
          onClick={handleRun}
          disabled={running}
          title={
            runState && runState !== 'idle' && runState !== 'running'
              ? `Last run: ${runState.ok ? 'ok' : 'fail'} — ${runState.message || ''}`
              : `Run this policy now (spawns agentctl with the manifest)`
          }
        >
          {running ? '…' : lastOk === true ? '✓ Ran' : lastOk === false ? '✗ Failed' : '▶ Run'}
        </button>
        <button className="policy-card__edit-btn" onClick={() => onEdit(policy)}>
          Edit policy
        </button>
      </div>
    </div>
  );
}
