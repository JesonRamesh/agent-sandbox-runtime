import './AgentTabs.css';

interface Props {
  agents: string[];
  activeAgent: string | null;
  onSelectAgent: (name: string) => void;
}

export default function AgentTabs({ agents, activeAgent, onSelectAgent }: Props) {
  if (!agents || agents.length === 0) {
    return (
      <div className="agent-tabs agent-tabs--empty">
        <span>no agents yet</span>
      </div>
    );
  }
  return (
    <div className="agent-tabs" role="tablist">
      {agents.map((name) => {
        const active = name === activeAgent;
        return (
          <button
            key={name}
            role="tab"
            aria-selected={active}
            className={`agent-tabs__tab ${active ? 'is-active' : ''}`}
            onClick={() => onSelectAgent(name)}
          >
            {name}
          </button>
        );
      })}
    </div>
  );
}
