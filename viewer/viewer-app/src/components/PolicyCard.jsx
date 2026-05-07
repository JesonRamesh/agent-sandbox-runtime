import './PolicyCard.css';

const MODE_LABELS = {
  enforce: { label: 'ENFORCE', cls: 'policy-card__mode--enforce' },
  audit:   { label: 'AUDIT',   cls: 'policy-card__mode--audit'   },
};

function RuleCount({ count, label }) {
  return (
    <div className="policy-card__rule">
      <span className="policy-card__rule-count">{count}</span>
      <span className="policy-card__rule-label">{label}</span>
    </div>
  );
}

export default function PolicyCard({ policy, onEdit }) {
  const mode = MODE_LABELS[policy.mode] || { label: policy.mode?.toUpperCase() || 'UNKNOWN', cls: '' };

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
          {policy.allowed_hosts.slice(0, 3).map((h, i) => (
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
        <button className="policy-card__edit-btn" onClick={() => onEdit(policy)}>
          Edit policy
        </button>
      </div>
    </div>
  );
}