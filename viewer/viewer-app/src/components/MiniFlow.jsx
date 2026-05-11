import { memo } from "react";
import "./MiniFlow.css";

const NODE_CONFIG = {
  session_start: { icon: String.fromCodePoint(0x25B6), label: "Start",   color: "var(--accent-emerald)", shape: "circle" },
  user_input:    { icon: String.fromCodePoint(0x1F4AC), label: "Task",    color: "var(--accent-blue)",    shape: "rect"   },
  tool_call:     { icon: String.fromCodePoint(0x1F310), label: "Fetch",   color: "var(--accent-blue)",    shape: "rect"   },
  tool_result:   { icon: "✓",  label: "Result",  color: "var(--accent-emerald)", shape: "rect"   },
  agent_output:  { icon: String.fromCodePoint(0x1F4A1), label: "Answer",  color: "var(--accent-purple)",  shape: "rect"   },
  stopped:       { icon: "✓",  label: "Done",    color: "var(--accent-emerald)", shape: "circle" },
  crashed:       { icon: "✕",  label: "Crashed", color: "var(--accent-crimson)", shape: "circle" },
};

const SHOW_TYPES = new Set(["session_start","user_input","tool_call","agent_output","stopped","crashed"]);
const MAX_NODES = 9;

function buildNodes(events) {
  const filtered = events.filter((e) => SHOW_TYPES.has(e.type));
  if (filtered.length === 0) return [];
  if (filtered.length > MAX_NODES) {
    return [
      ...filtered.slice(0, 2),
      { _id: "ellipsis", type: "__ellipsis", _count: filtered.length - MAX_NODES + 3 },
      ...filtered.slice(-(MAX_NODES - 3)),
    ];
  }
  return filtered;
}

function MiniNode({ event, isActive, isBlocked }) {
  const cfg = NODE_CONFIG[event.type];
  if (!cfg) return null;
  const color = isBlocked ? "var(--accent-crimson)" : cfg.color;
  return (
    <div
      className={["mf-node", "mf-node--" + cfg.shape, isActive && "mf-node--active", isBlocked && "mf-node--blocked"].filter(Boolean).join(" ")}
      style={{ "--node-color": color }}
      title={cfg.label}
    >
      <span className="mf-node__icon">{isBlocked ? "✕" : cfg.icon}</span>
      <span className="mf-node__label">{isBlocked ? "Blocked" : cfg.label}</span>
    </div>
  );
}

function EllipsisNode({ count }) {
  return (
    <div className="mf-node mf-node--ellipsis">
      <span className="mf-node__icon">···</span>
      <span className="mf-node__label">+{count}</span>
    </div>
  );
}

function Connector({ animated, danger }) {
  const cls = ["mf-connector", animated && "mf-connector--animated", danger && "mf-connector--danger"].filter(Boolean).join(" ");
  return (
    <div className={cls}>
      <div className="mf-connector__line" />
      <div className="mf-connector__arrow">›</div>
    </div>
  );
}

const MiniFlow = memo(function MiniFlow({ llmEvents, kernelEvents, injectionTargets }) {
  const nodes = buildNodes(llmEvents);
  if (nodes.length === 0) {
    return (
      <div className="mini-flow mini-flow--empty">
        <span className="mini-flow__empty">Waiting for agent session…</span>
      </div>
    );
  }
  const lastNode = nodes[nodes.length - 1];
  const isRunning = !["stopped","crashed","__ellipsis"].includes(lastNode.type);
  const blockedIds = injectionTargets || new Set();
  const hasBlocked = kernelEvents.some((e) => e.type === "connect_blocked");
  return (
    <div className="mini-flow">
      <div className="mini-flow__label">Session flow</div>
      <div className="mini-flow__track">
        {nodes.map((node, i) => {
          const isLast    = i === nodes.length - 1;
          const isActive  = isLast && isRunning;
          const isBlocked = blockedIds.has(node._id);
          const isDanger  = isBlocked;
          return (
            <div key={node._id} className="mf-step">
              {node.type === "__ellipsis"
                ? <EllipsisNode count={node._count} />
                : <MiniNode event={node} isActive={isActive} isBlocked={isBlocked} />}
              {!isLast && <Connector animated={isActive} danger={isDanger} />}
            </div>
          );
        })}
        {isRunning && (
          <div className="mf-step">
            <Connector animated />
            <div className="mf-node mf-node--pulse" style={{ "--node-color": "var(--accent-blue)" }}>
              <span className="mf-node__icon">◉</span>
              <span className="mf-node__label">Live</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
});

export default MiniFlow;
