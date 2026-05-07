import './StatsRow.css';

function formatUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  const m = Math.floor(s / 60);
  const r = s % 60;
  if (m === 0) return `${r}s`;
  return `${m}m ${r.toString().padStart(2, '0')}s`;
}

// Render allowed/blocked side-by-side inside one pillar card so an operator
// can scan four pillars in one row without losing the comparison.
function PillarStat({ id, label, allowed, blocked, pulseKey }) {
  const isPulsing = blocked > 0 && pulseKey > 0;
  const key = isPulsing ? `${id}-${pulseKey}` : id;
  return (
    <div key={key} className={`stats-row__card pillar-card${isPulsing ? ' is-pulsing' : ''}`}>
      <div className="stats-row__label">{label}</div>
      <div className="pillar-card__split">
        <div className="pillar-card__half tone-good">
          <span className="pillar-card__value">{allowed}</span>
          <span className="pillar-card__sub">allowed</span>
        </div>
        <div className="pillar-card__divider" />
        <div className="pillar-card__half tone-bad">
          <span className="pillar-card__value">{blocked}</span>
          <span className="pillar-card__sub">blocked</span>
        </div>
      </div>
    </div>
  );
}

export default function StatsRow({ stats, blockedPulseKey = 0 }) {
  const s = stats || {};
  return (
    <div className="stats-row">
      <PillarStat id="net"  label="network"     allowed={s.netAllowed  || 0} blocked={s.netBlocked  || 0} pulseKey={blockedPulseKey} />
      <PillarStat id="file" label="filesystem"  allowed={s.fileAllowed || 0} blocked={s.fileBlocked || 0} pulseKey={blockedPulseKey} />
      <PillarStat id="exec" label="exec"        allowed={s.execAllowed || 0} blocked={s.execBlocked || 0} pulseKey={blockedPulseKey} />
      <PillarStat id="cred" label="credentials" allowed={s.credAllowed || 0} blocked={s.credBlocked || 0} pulseKey={blockedPulseKey} />
      <div className="stats-row__card stats-row__card--meta">
        <div className="stats-row__value">{s.toolCalls || 0}</div>
        <div className="stats-row__label">tool calls</div>
      </div>
      <div className="stats-row__card stats-row__card--meta">
        <div className="stats-row__value">{formatUptime(s.uptime)}</div>
        <div className="stats-row__label">uptime</div>
      </div>
    </div>
  );
}
