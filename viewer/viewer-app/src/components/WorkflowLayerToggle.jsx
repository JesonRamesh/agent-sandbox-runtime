const LAYERS = [
  { id: 'unified', label: 'Unified',         icon: '◈' },
  { id: 'agent',   label: 'Agent Activity',  icon: '◉' },
  { id: 'kernel',  label: 'Kernel Verdicts', icon: '⬡' },
];

export default function WorkflowLayerToggle({ activeLayer, onSwitch }) {
  return (
    <div className="wf-layer-toggle">
      <span className="wf-layer-toggle__heading">View</span>
      <div className="wf-layer-toggle__pills">
        {LAYERS.map((l) => (
          <button
            key={l.id}
            className={`wf-layer-toggle__btn${activeLayer === l.id ? ' is-active' : ''}`}
            onClick={() => onSwitch(l.id)}
          >
            <span className="wf-layer-toggle__icon">{l.icon}</span>
            <span className="wf-layer-toggle__label">{l.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}