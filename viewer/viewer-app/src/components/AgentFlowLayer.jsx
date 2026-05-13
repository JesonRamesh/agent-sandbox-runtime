import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactFlow, {
  Background, Controls, Handle, Position,
  ReactFlowProvider, useReactFlow,
} from 'reactflow';
import 'reactflow/dist/style.css';

// ─── Layout ───────────────────────────────────────────────────────────────────
const NODE_X    = 60;
const NODE_GAP  = 156;
const START_Y   = 50;
const CARD_W    = 340;
const CIRCLE_W  = 120;
const MATCH_WIN = 10; // seconds — same window used in UnifiedFlowLayer

// ─── Helpers ──────────────────────────────────────────────────────────────────
function trunc(str, n) {
  if (!str) return '';
  str = String(str);
  return str.length > n ? str.slice(0, n) + '\u2026' : str;
}

function extractHostname(url) {
  try { return new URL(url).hostname; } catch { return trunc(url, 40); }
}

function formatDelta(seconds) {
  if (seconds == null || isNaN(seconds)) return null;
  if (seconds < 0.01) return '<0.01s';
  if (seconds < 1)    return `${(seconds * 1000).toFixed(0)}ms`;
  if (seconds < 10)   return `${seconds.toFixed(1)}s`;
  return `${Math.round(seconds)}s`;
}

// ─── Pre-process LLM events ───────────────────────────────────────────────────
// Drops raw stdout lines, merges tool_call + tool_result into one record,
// and injects a lightweight "reasoning" node wherever a stdout line contains
// thinking-related language OR whenever a gap ≥ 1.2 s exists between events.
function preprocessAgentEvents(llmEvents) {
  // 1. keep only agent-meaningful events
  const filtered = llmEvents.filter((e) => e.type !== 'stdout' || isThinkingLine(e));

  const result = [];
  let i = 0;
  while (i < filtered.length) {
    const e = filtered[i];

    // Merge tool_call + following tool_result
    if (e.type === 'tool_call') {
      const next = filtered[i + 1];
      if (next && next.type === 'tool_result' && next.data?.tool === e.data?.tool) {
        const durationSec = (next.ts != null && e.ts != null) ? next.ts - e.ts : null;
        result.push({ ...e, _result: next.data, _duration: durationSec });
        i += 2;
        continue;
      }
      result.push({ ...e, _result: null, _duration: null });
      i++;
      continue;
    }

    // Promote thinking stdout → reasoning node
    if (e.type === 'stdout' && isThinkingLine(e)) {
      result.push({ ...e, type: 'reasoning', _synthetic: false });
      i++;
      continue;
    }

    result.push(e);
    i++;
  }
  return result;
}

function isThinkingLine(e) {
  if (e.type !== 'stdout') return false;
  const line = (e.data?.line || '').toLowerCase();
  return (
    line.includes('think') ||
    line.includes('plan') ||
    line.includes('reason') ||
    line.includes('analys') ||
    line.includes('decid') ||
    line.includes('consider')
  );
}

// ─── Node renderers ───────────────────────────────────────────────────────────

// Bookend circle — session start / stop / crash
function AgentCircleNode({ data }) {
  return (
    <>
      {!data.isStart    && <Handle type="target" position={Position.Top} />}
      <div className={`afl-circle afl-circle--${data.variant}`}>
        <span className="afl-circle__icon">{data.icon}</span>
        <span className="afl-circle__label">{data.label}</span>
        {data.sub && <span className="afl-circle__sub">{data.sub}</span>}
      </div>
      {!data.isTerminal && <Handle type="source" position={Position.Bottom} />}
    </>
  );
}

// Task card — user_input
function AgentTaskNode({ data }) {
  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div className="afl-card afl-card--task">
        <div className="afl-card__header">
          <span className="afl-card__icon">💬</span>
          <span className="afl-card__type">Task received</span>
          <span className="afl-card__step">#{data.step}</span>
        </div>
        <div className="afl-card__body">{data.text}</div>
      </div>
      <Handle type="source" position={Position.Bottom} />
    </>
  );
}

// Reasoning card — synthesised from stdout thinking lines
function AgentReasoningNode({ data }) {
  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div className="afl-card afl-card--reasoning">
        <div className="afl-card__header">
          <span className="afl-card__icon">🧠</span>
          <span className="afl-card__type">Reasoning</span>
        </div>
        <div className="afl-card__body afl-card__body--dim">{data.text}</div>
      </div>
      <Handle type="source" position={Position.Bottom} />
    </>
  );
}

// Tool card — tool_call (+ merged tool_result)
function AgentToolNode({ data }) {
  const statusCls = data.statusVariant ? `afl-card__status--${data.statusVariant}` : '';
  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div className={`afl-card afl-card--tool${data.blocked ? ' afl-card--blocked' : data.ok ? ' afl-card--ok' : ''}`}>
        <div className="afl-card__header">
          <span className="afl-card__icon">{data.icon}</span>
          <span className="afl-card__type">{data.typeLabel}</span>
          <span className="afl-card__step">#{data.step}</span>
        </div>

        {/* Target host */}
        <div className="afl-card__body">{data.target}</div>

        {/* Arg row — show URL or key args */}
        {data.argLine && (
          <div className="afl-card__arg">
            <span className="afl-card__arg-key">url</span>
            <span className="afl-card__arg-val">{data.argLine}</span>
          </div>
        )}

        {/* Outcome row */}
        {data.status && (
          <div className={`afl-card__status ${statusCls}`}>{data.status}</div>
        )}

        {/* Duration badge */}
        {data.duration && (
          <div className="afl-card__duration">{data.duration}</div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} />
    </>
  );
}

// Answer card — agent_output
function AgentOutputNode({ data }) {
  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div className="afl-card afl-card--output">
        <div className="afl-card__header">
          <span className="afl-card__icon">💡</span>
          <span className="afl-card__type">Agent answer</span>
          <span className="afl-card__step">#{data.step}</span>
        </div>
        <div className="afl-card__body">{data.text}</div>
      </div>
      <Handle type="source" position={Position.Bottom} />
    </>
  );
}

const nodeTypes = {
  'afl-circle':   AgentCircleNode,
  'afl-task':     AgentTaskNode,
  'afl-reasoning': AgentReasoningNode,
  'afl-tool':     AgentToolNode,
  'afl-output':   AgentOutputNode,
};

// ─── Auto-follow (identical pattern to UnifiedFlowLayer) ─────────────────────
const FOLLOW_ZOOM = 0.78;

function AutoFollow({ nodeCount, nodes, following, containerRef }) {
  const { setViewport } = useReactFlow();

  useEffect(() => {
    if (!following || nodes.length === 0) return;
    let bottom = nodes[0];
    for (const n of nodes) {
      if ((n.position?.y || 0) > (bottom.position?.y || 0)) bottom = n;
    }
    const el = containerRef?.current;
    const cW = el ? el.clientWidth  : 900;
    const cH = el ? el.clientHeight : 600;
    const nW = bottom.style?.width ? parseInt(bottom.style.width) : CIRCLE_W;
    const nH = bottom.type === 'afl-circle' ? CIRCLE_W : 110;
    const cx = (bottom.position.x || 0) + nW / 2;
    const cy = (bottom.position.y || 0) + nH / 2;
    const tx = cW / 2 - cx * FOLLOW_ZOOM;
    const ty = cH / 2 - cy * FOLLOW_ZOOM;
    const t = setTimeout(() => {
      setViewport({ x: tx, y: ty, zoom: FOLLOW_ZOOM }, { duration: 280 });
    }, 60);
    return () => clearTimeout(t);
  }, [nodeCount, following, nodes, setViewport, containerRef]);

  return null;
}

// ─── Event → graph conversion ─────────────────────────────────────────────────
function buildAgentGraph(llmEvents, kernelEvents) {
  // Group by agent
  const byAgent = new Map();
  for (const e of llmEvents) {
    const a = e.agent || 'unknown';
    if (!byAgent.has(a)) byAgent.set(a, []);
    byAgent.get(a).push(e);
  }

  // Build blocked-host set per agent from kernel events
  const blockedHosts = new Set();
  for (const e of kernelEvents) {
    if (e.type === 'connect_blocked') {
      const h = e.data?.hostname || e.data?.dst_ip;
      if (h) blockedHosts.add(h);
    }
  }

  const COL_WIDTH = CARD_W + 120;
  const nodes = [];
  const edges = [];
  const agents = [...byAgent.keys()];

  agents.forEach((agent, agentIdx) => {
    const colX   = agentIdx * COL_WIDTH;
    const cardX  = colX + NODE_X;
    const circleX = colX + NODE_X + (CARD_W - CIRCLE_W) / 2;

    const rawEvents  = byAgent.get(agent);
    const processed  = preprocessAgentEvents(rawEvents);

    let y      = START_Y;
    let prevId = null;
    let prevTs = null;
    let step   = 0;

    for (const event of processed) {
      const id = `afl-${event._id}`;

      if (event.type === 'session_start') {
        const d = event.data || {};
        nodes.push({
          id, type: 'afl-circle',
          position: { x: circleX, y },
          data: {
            variant: 'start', isStart: true,
            icon: '▶', label: 'Session Start',
            sub: d.launch_mode ? `${agent} · ${d.launch_mode}` : agent,
          },
        });
        y += 150;

      } else if (event.type === 'stopped') {
        const d = event.data || {};
        nodes.push({
          id, type: 'afl-circle',
          position: { x: circleX, y },
          data: {
            variant: 'complete', isTerminal: true,
            icon: '✓', label: 'Done',
            sub: d.exit_code === 0 || d.exit_code == null ? 'finished successfully' : `exit ${d.exit_code}`,
          },
        });
        y += 150;

      } else if (event.type === 'crashed') {
        const d = event.data || {};
        nodes.push({
          id, type: 'afl-circle',
          position: { x: circleX, y },
          data: {
            variant: 'crashed', isTerminal: true,
            icon: '✕', label: 'Crashed',
            sub: `exit ${d.exit_code ?? '?'}`,
          },
        });
        y += 150;

      } else if (event.type === 'user_input') {
        step++;
        const text = trunc(event.data?.text || '', 120);
        nodes.push({
          id, type: 'afl-task',
          position: { x: cardX, y },
          data: { step, text },
          style: { width: `${CARD_W}px` },
        });
        y += NODE_GAP;

      } else if (event.type === 'reasoning') {
        const text = trunc(event.data?.line || '', 100);
        nodes.push({
          id, type: 'afl-reasoning',
          position: { x: cardX, y },
          data: { text },
          style: { width: `${CARD_W}px` },
        });
        y += NODE_GAP;

      } else if (event.type === 'tool_call') {
        step++;
        const d    = event.data || {};
        const r    = event._result;
        const url  = d.args?.url || '';
        const host = url ? extractHostname(url) : (d.tool || 'tool');

        const ready    = r !== null && r !== undefined;
        const ok       = ready && r.ok !== false;
        const blocked  = ready && !ok;
        // Also check if host appears in kernel blocked set
        const kernelBlocked = blockedHosts.has(host);
        const isBlocked = blocked || kernelBlocked;

        const target  = url ? `${isBlocked ? 'Attempted: ' : 'Fetching: '}${host}` : (d.tool || 'unknown tool');
        const argLine = url ? trunc(url, 48) : null;

        let status, statusVariant;
        if (!ready) {
          status = '⏳  Awaiting response…';
          statusVariant = 'pending';
        } else if (ok) {
          status = `✓  ${r.chars ?? '?'} chars received`;
          statusVariant = 'ok';
        } else {
          status = '✗  Blocked by kernel policy';
          statusVariant = 'fail';
        }

        const duration = event._duration ? formatDelta(event._duration) : null;

        nodes.push({
          id, type: 'afl-tool',
          position: { x: cardX, y },
          data: {
            step,
            icon:        isBlocked ? '🚫' : '🌐',
            typeLabel:   isBlocked ? 'Blocked request' : 'Tool call',
            target, argLine, status, statusVariant,
            ok:      !isBlocked && ready,
            blocked: isBlocked,
            duration,
          },
          style:     { width: `${CARD_W}px` },
          className: isBlocked ? 'afl-node--blocked' : '',
        });
        y += NODE_GAP;

      } else if (event.type === 'agent_output') {
        step++;
        const d    = event.data || {};
        const text = d.text || '';
        nodes.push({
          id, type: 'afl-output',
          position: { x: cardX, y },
          data: { step, text: trunc(text, 180) },
          style: { width: `${CARD_W}px` },
        });
        y += NODE_GAP;
      }
      // skip all other types (tool_result already merged, raw stdout dropped)

      // Draw edge from previous node
      if (prevId) {
        const dt = (prevTs != null && event.ts != null) ? event.ts - prevTs : null;
        const timeLabel = formatDelta(dt);
        const isBlocked = nodes[nodes.length - 1]?.className === 'afl-node--blocked';
        edges.push({
          id:     `afl-e-${prevId}-${id}`,
          source: prevId,
          target: id,
          type:   'smoothstep',
          animated: isBlocked,
          style: {
            stroke:      isBlocked ? '#ff4d5e' : '#2a3550',
            strokeWidth: isBlocked ? 2.5 : 2,
          },
          ...(timeLabel && {
            label:          timeLabel,
            labelStyle:     { fill: '#5a647a', fontSize: 10, fontFamily: 'var(--mono)', fontWeight: 600 },
            labelBgStyle:   { fill: '#0d1117', fillOpacity: 0.85 },
            labelBgPadding: [4, 6],
            labelBgBorderRadius: 3,
          }),
        });
      }

      prevId = id;
      prevTs = event.ts;
    }
  });

  return { nodes, edges };
}

// ─── Summary ribbon ───────────────────────────────────────────────────────────
function computeAgentStats(llmEvents, kernelEvents) {
  const meaningful = llmEvents.filter((e) =>
    ['user_input', 'tool_call', 'agent_output', 'session_start', 'stopped', 'crashed'].includes(e.type)
  );
  if (meaningful.length === 0) return null;

  const firstTs = meaningful[0]?.ts;
  const lastTs  = meaningful[meaningful.length - 1]?.ts;
  const duration = (firstTs != null && lastTs != null) ? lastTs - firstTs : null;

  let toolCalls = 0;
  const toolsSeen = new Set();
  let blocked = 0;

  for (const e of llmEvents) {
    if (e.type === 'tool_call') {
      toolCalls++;
      toolsSeen.add(e.data?.tool || 'unknown');
    }
  }
  for (const e of kernelEvents) {
    if (e.type === 'connect_blocked') blocked++;
  }

  const successRate = toolCalls > 0
    ? Math.round(((toolCalls - blocked) / toolCalls) * 100)
    : null;

  return { duration, toolCalls, uniqueTools: toolsSeen.size, blocked, successRate };
}

function AgentSummary({ stats }) {
  if (!stats) return null;
  const dur = stats.duration != null
    ? (stats.duration < 10 ? `${stats.duration.toFixed(1)}s` : `${Math.round(stats.duration)}s`)
    : '\u2014';
  return (
    <div className="afl-summary">
      <span className="afl-summary__item">
        <span className="afl-summary__label">Duration</span>
        <span className="afl-summary__value">{dur}</span>
      </span>
      <span className="afl-summary__sep">│</span>
      <span className="afl-summary__item">
        <span className="afl-summary__label">Tool calls</span>
        <span className="afl-summary__value">{stats.toolCalls}</span>
      </span>
      <span className="afl-summary__sep">│</span>
      <span className="afl-summary__item">
        <span className="afl-summary__label">Unique tools</span>
        <span className="afl-summary__value">{stats.uniqueTools}</span>
      </span>
      <span className="afl-summary__sep">│</span>
      <span className="afl-summary__item">
        <span className="afl-summary__label">Blocked</span>
        <span className={`afl-summary__value${stats.blocked > 0 ? ' afl-summary__value--danger' : ''}`}>
          {stats.blocked}
        </span>
      </span>
      {stats.successRate !== null && (
        <>
          <span className="afl-summary__sep">│</span>
          <span className="afl-summary__item">
            <span className="afl-summary__label">Success rate</span>
            <span className={`afl-summary__value${stats.successRate < 50 ? ' afl-summary__value--danger' : ' afl-summary__value--good'}`}>
              {stats.successRate}%
            </span>
          </span>
        </>
      )}
    </div>
  );
}

// ─── Exported component ───────────────────────────────────────────────────────
export default function AgentFlowLayer({ llmEvents, kernelEvents }) {
  const { nodes, edges } = useMemo(
    () => buildAgentGraph(llmEvents, kernelEvents),
    [llmEvents, kernelEvents],
  );

  const stats = useMemo(
    () => computeAgentStats(llmEvents, kernelEvents),
    [llmEvents, kernelEvents],
  );

  const [following, setFollowing]   = useState(true);
  const userPannedRef               = useRef(false);
  const containerRef                = useRef(null);

  const handleMoveStart = useCallback((e) => {
    if (e) userPannedRef.current = true;
    else   userPannedRef.current = false;
  }, []);

  const handleMoveEnd = useCallback(() => {
    if (userPannedRef.current) setFollowing(false);
  }, []);

  const resumeFollowing = useCallback(() => {
    setFollowing(true);
    userPannedRef.current = false;
  }, []);

  if (nodes.length === 0) {
    return (
      <div className="wf-empty" style={{ flex: 1 }}>
        <span className="wf-empty__icon">⏳</span>
        <span className="wf-empty__title">Waiting for agent session…</span>
        <span className="wf-empty__sub">Agent activity will appear here as events arrive.</span>
      </div>
    );
  }

  return (
    <>
      <AgentSummary stats={stats} />
      <div ref={containerRef} style={{ flex: 1, minHeight: 0, position: 'relative' }}>
        <ReactFlowProvider>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.3, maxZoom: FOLLOW_ZOOM, minZoom: 0.1 }}
            minZoom={0.1}
            maxZoom={1.5}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
            onMoveStart={handleMoveStart}
            onMoveEnd={handleMoveEnd}
          >
            <AutoFollow
              nodeCount={nodes.length}
              nodes={nodes}
              following={following}
              containerRef={containerRef}
            />
            <Background color="#1c2536" gap={24} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
          {!following && (
            <button className="wf-follow-btn" onClick={resumeFollowing}>
              ↓ Follow latest
            </button>
          )}
        </ReactFlowProvider>
      </div>
    </>
  );
}