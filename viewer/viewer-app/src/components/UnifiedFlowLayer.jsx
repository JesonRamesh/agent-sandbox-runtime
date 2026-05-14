import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactFlow, {
  Background, Controls, Handle, Position,
  ReactFlowProvider, useReactFlow,
} from 'reactflow';
import 'reactflow/dist/style.css';

// ─── Layout ──────────────────────────────────────────────────────────────────
const MAIN_X        = 80;
const KERNEL_X      = 440;
const NODE_GAP      = 140;
const PHASE_GAP     = 180;
const START_Y       = 50;
const COL_WIDTH     = 740;
const CARD_WIDTH    = 280;
const CARD_WIDTH_LG = 320;
const MATCH_WIN     = 10;

const PHASE_TASK   = new Set(['session_start', 'user_input']);
const PHASE_EXEC   = new Set(['tool_call']);
const PHASE_RESULT = new Set(['agent_output', 'stopped', 'crashed']);

// ─── Helpers ─────────────────────────────────────────────────────────────────
function trunc(str, n) {
  if (!str) return '';
  str = String(str);
  return str.length > n ? str.slice(0, n) + '…' : str;
}

function extractHostname(url) {
  try { return new URL(url).hostname; } catch { return trunc(url, 35); }
}

function formatDelta(seconds) {
  if (seconds == null || isNaN(seconds)) return null;
  if (seconds < 0.01) return '<0.01s';
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  if (seconds < 10) return `${seconds.toFixed(1)}s`;
  return `${Math.round(seconds)}s`;
}

// ─── Custom node: main chain events ──────────────────────────────────────────
function EventNode({ data }) {
  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div className={`wf-card wf-card--${data.variant}`}>
        <div className="wf-card__header">
          <span className="wf-card__icon">{data.icon}</span>
          <span className="wf-card__type">{data.typeLabel}</span>
          {data.step != null && (
            <span className="wf-card__step">#{data.step}</span>
          )}
        </div>
        {data.detail && (
          <div className="wf-card__detail">{data.detail}</div>
        )}
        {data.status && (
          <div className={`wf-card__status wf-card__status--${data.statusVariant}`}>
            {data.status}
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} />
      <Handle type="source" position={Position.Right} id="right" />
    </>
  );
}

// ─── Custom node: circle bookends ────────────────────────────────────────────
function CircleNode({ data }) {
  return (
    <>
      {!data.isStart    && <Handle type="target" position={Position.Top} />}
      <div className={`wf-circle wf-circle--${data.variant}`}>
        <span className="wf-circle__icon">{data.icon}</span>
        <span className="wf-circle__label">{data.label}</span>
        {data.sub && <span className="wf-circle__sub">{data.sub}</span>}
      </div>
      {!data.isTerminal && <Handle type="source" position={Position.Bottom} />}
    </>
  );
}

// ─── Custom node: kernel outcome card ────────────────────────────────────────
function KernelNode({ data }) {
  const blocked = data.variant === 'blocked';
  return (
    <>
      <Handle type="target" position={Position.Left} />
      <div className={`wf-kernel wf-kernel--${data.variant}`}>
        <div className="wf-kernel__header">
          <span className="wf-kernel__icon">{blocked ? '🛡' : '✓'}</span>
          <span className="wf-kernel__type">
            {blocked ? 'Attack Blocked by Kernel' : 'Connection Permitted'}
          </span>
        </div>
        <div className="wf-kernel__host">{data.host}</div>
        <div className="wf-kernel__reason">
          {blocked
            ? (data.reason
                ? `Not in allowed_hosts \u2014 ${data.reason}`
                : 'Not listed in the allowed_hosts policy')
            : (data.reason
                ? `Matches policy \u2014 ${data.reason}`
                : 'Listed in allowed_hosts policy')}
        </div>
      </div>
    </>
  );
}

// ─── Custom node: annotation badge ───────────────────────────────────────────
function AnnotationNode({ data }) {
  return (
    <div className={`wf-annotation wf-annotation--${data.variant}`}>
      <span className="wf-annotation__icon">{data.icon}</span>
      <span className="wf-annotation__text">{data.text}</span>
    </div>
  );
}

const nodeTypes = {
  event:      EventNode,
  circle:     CircleNode,
  kernel:     KernelNode,
  annotation: AnnotationNode,
};

// ─── Auto-follow ──────────────────────────────────────────────────────────────
const FOLLOW_ZOOM = 0.75;

function AutoFollow({ nodeCount, nodes, following, containerRef }) {
  const { setViewport } = useReactFlow();

  useEffect(() => {
    if (!following || nodes.length === 0) return;

    let bottomNode = nodes[0];
    for (const n of nodes) {
      if ((n.position?.y || 0) > (bottomNode.position?.y || 0)) bottomNode = n;
    }

    const el = containerRef?.current;
    const containerW = el ? el.clientWidth  : 900;
    const containerH = el ? el.clientHeight : 600;

    const nodeH  = bottomNode.type === 'circle' ? 120 : 110;
    const nodeW  = bottomNode.style?.width ? parseInt(bottomNode.style.width) : 280;
    const nodeCX = (bottomNode.position?.x || 0) + nodeW / 2;
    const nodeCY = (bottomNode.position?.y || 0) + nodeH / 2;

    const targetX = containerW / 2 - nodeCX * FOLLOW_ZOOM;
    const targetY = containerH / 2 - nodeCY * FOLLOW_ZOOM;

    const t = setTimeout(() => {
      setViewport({ x: targetX, y: targetY, zoom: FOLLOW_ZOOM }, { duration: 280 });
    }, 60);

    return () => clearTimeout(t);
  }, [nodeCount, following, nodes, setViewport, containerRef]);

  return null;
}

// ─── Pre-process: drop stdout, merge tool_call + tool_result ─────────────────
function preprocessLlm(events) {
  const filtered = events.filter((e) => e.type !== 'stdout');
  const result = [];
  let i = 0;
  while (i < filtered.length) {
    const e = filtered[i];
    if (e.type === 'tool_call') {
      const next = filtered[i + 1];
      if (next && next.type === 'tool_result' && next.data?.tool === e.data?.tool) {
        result.push({ ...e, _result: next.data });
        i += 2;
      } else {
        result.push({ ...e, _result: null });
        i += 1;
      }
    } else {
      result.push(e);
      i += 1;
    }
  }
  return result;
}

// ─── Node data builders ───────────────────────────────────────────────────────
const CIRCLE_TYPES = new Set(['session_start', 'stopped', 'crashed']);

function buildCircleData(event) {
  const d = event.data || {};
  switch (event.type) {
    case 'session_start':
      return {
        variant: 'start', isStart: true,
        icon: '▶', label: 'Session Started',
        sub: d.launch_mode
          ? `${event.agent} · ${d.launch_mode} mode`
          : (event.agent || 'agent'),
      };
    case 'stopped':
      return {
        variant: 'complete', isTerminal: true,
        icon: '✓', label: 'Task Complete',
        sub: d.exit_code === 0 || d.exit_code == null
          ? 'finished successfully'
          : `exit code ${d.exit_code}`,
      };
    case 'crashed':
      return {
        variant: 'crashed', isTerminal: true,
        icon: '✕', label: 'Agent Crashed',
        sub: `unexpected failure (code ${d.exit_code ?? '?'})`,
      };
    default:
      return null;
  }
}

function buildEventData(event, step) {
  const d = event.data || {};
  switch (event.type) {
    case 'user_input':
      return {
        variant: 'user', icon: '💬',
        typeLabel: 'Task Given',
        detail: `"${trunc(d.text || '', 72)}"`,
        step,
      };

    case 'tool_call': {
      const url      = d.args?.url || '';
      const hostname = url ? extractHostname(url) : '';
      const r        = event._result;
      const ready    = r !== null && r !== undefined;
      const ok       = ready && r.ok !== false;
      const isFail   = ready && !ok;

      const detail = url
        ? (isFail ? `Attempted to reach ${hostname}` : `Fetching data from ${hostname}`)
        : (d.tool || 'unknown tool');

      let status, statusVariant;
      if (!ready) {
        status = '⏳  Waiting for response…';
        statusVariant = 'pending';
      } else if (ok) {
        status = `✓  Received ${r.chars ?? '?'} characters successfully`;
        statusVariant = 'ok';
      } else {
        status = '✗  Blocked — connection denied by kernel';
        statusVariant = 'fail';
      }

      return {
        variant: ready ? (ok ? 'tool-ok' : 'tool-fail') : 'tool',
        icon: isFail ? '🚫' : '🌐',
        typeLabel: isFail ? 'Blocked Request' : 'Fetching URL',
        detail, status, statusVariant, step,
      };
    }

    case 'agent_output': {
      const text = d.text || '';
      const firstSentence = text.split(/[.!?]\s/)[0];
      return {
        variant: 'agent', icon: '💡',
        typeLabel: 'Agent Answer',
        detail: trunc(firstSentence, 72),
        step,
      };
    }

    default:
      return {
        variant: 'default', icon: '◆',
        typeLabel: event.type.replace(/_/g, ' '),
        detail: trunc(JSON.stringify(d), 55),
        step,
      };
  }
}

// ─── Core conversion ──────────────────────────────────────────────────────────
function convertEventsToGraph(llmEvents, kernelEvents) {
  const kernel = kernelEvents.filter((e) => e.type !== 'connect_attempt');

  const agentLlm    = new Map();
  const agentKernel = new Map();
  for (const e of llmEvents) {
    const a = e.agent || 'unknown';
    if (!agentLlm.has(a)) agentLlm.set(a, []);
    agentLlm.get(a).push(e);
  }
  for (const e of kernel) {
    const a = e.agent || 'unknown';
    if (!agentKernel.has(a)) agentKernel.set(a, []);
    agentKernel.get(a).push(e);
  }

  const nodes = [];
  const edges = [];
  const allAgents = [...new Set([...agentLlm.keys(), ...agentKernel.keys()])];

  allAgents.forEach((agent, agentIdx) => {
    const colX    = agentIdx * COL_WIDTH;
    const mainX   = colX + MAIN_X;
    const kernelX = colX + KERNEL_X;

    const llmList    = preprocessLlm(agentLlm.get(agent) || []);
    const kernelList = agentKernel.get(agent) || [];

    let y      = START_Y;
    let prevId = null;
    let prevTs = null;
    let step   = 0;
    const toolCallNodes = [];

    for (const event of llmList) {
      const id       = `n-${event._id}`;
      const isCircle = CIRCLE_TYPES.has(event.type);

      if (prevId && !isCircle) {
        const prevEvent = llmList[llmList.indexOf(event) - 1];
        if (prevEvent) {
          const prevPhase = PHASE_TASK.has(prevEvent.type) ? 'task'
            : PHASE_EXEC.has(prevEvent.type) ? 'exec' : 'result';
          const curPhase = PHASE_TASK.has(event.type) ? 'task'
            : PHASE_EXEC.has(event.type) ? 'exec' : 'result';
          if (prevPhase !== curPhase) y += (PHASE_GAP - NODE_GAP);
        }
      }

      if (isCircle) {
        const cData = buildCircleData(event);
        nodes.push({
          id, type: 'circle',
          position: { x: mainX + (CARD_WIDTH - 120) / 2, y },
          data: cData,
        });
      } else {
        step += 1;
        const eData  = buildEventData(event, step);
        const isWide = event.type === 'user_input' || event.type === 'agent_output';
        const width  = isWide ? CARD_WIDTH_LG : CARD_WIDTH;
        nodes.push({
          id, type: 'event',
          position: { x: mainX, y },
          data: eData,
          style: { width: `${width}px` },
        });
        if (event.type === 'tool_call') toolCallNodes.push({ id, ts: event.ts, y });
      }

      if (prevId) {
        const dt = (prevTs != null && event.ts != null) ? event.ts - prevTs : null;
        const timeLabel = formatDelta(dt);
        edges.push({
          id: `e-${prevId}-${id}`,
          source: prevId, target: id,
          type: 'smoothstep',
          style: { stroke: '#2a3550', strokeWidth: 2 },
          ...(timeLabel && {
            label: timeLabel,
            labelStyle: { fill: '#5a647a', fontSize: 10, fontFamily: 'var(--mono)', fontWeight: 600 },
            labelBgStyle: { fill: '#0d1117', fillOpacity: 0.85 },
            labelBgPadding: [4, 6],
            labelBgBorderRadius: 3,
          }),
        });
      }
      prevId = id;
      prevTs = event.ts;
      y += isCircle ? 150 : NODE_GAP;
    }

    // ── Identify blocked tool_calls ───────────────────────────────────────────
    const blockedToolIds = new Set();
    for (const ke of kernelList) {
      if (ke.type !== 'connect_blocked') continue;
      for (let i = toolCallNodes.length - 1; i >= 0; i--) {
        const tc = toolCallNodes[i];
        const dt = ke.ts - tc.ts;
        if (dt >= 0 && dt <= MATCH_WIN) { blockedToolIds.add(tc.id); break; }
      }
    }

    // ── Mark blocked nodes ────────────────────────────────────────────────────
    for (const node of nodes) {
      if (blockedToolIds.has(node.id)) node.className = 'wf-node--danger';
    }

    // ── Recolor main-chain edges ──────────────────────────────────────────────
    for (const edge of edges) {
      if (!edge.id.startsWith('e-')) continue;
      const targetNode = nodes.find((n) => n.id === edge.target);
      if (targetNode && blockedToolIds.has(targetNode.id)) {
        edge.style = { stroke: '#ff4d5e', strokeWidth: 2.5 };
        edge.animated = true;
      } else if (targetNode && targetNode.data?.variant === 'tool-ok') {
        edge.style = { stroke: '#2d4a3a', strokeWidth: 2 };
      }
    }

    // ── Kernel nodes ──────────────────────────────────────────────────────────
    const usedTc = new Map();
    for (const ke of kernelList) {
      const kid     = `n-${ke._id}`;
      const variant = ke.type === 'connect_blocked' ? 'blocked' : 'allowed';
      const kd      = ke.data || {};
      const host    = kd.hostname || `${kd.dst_ip || '?'}:${kd.dst_port || '?'}`;

      let best = null;
      for (let i = toolCallNodes.length - 1; i >= 0; i--) {
        const tc = toolCallNodes[i];
        const dt = ke.ts - tc.ts;
        if (dt >= 0 && dt <= MATCH_WIN) { best = tc; break; }
      }

      const offset = best ? (usedTc.get(best.id) || 0) * 140 : 0;
      const nodeY  = best ? best.y + 15 + offset : y;
      if (best) usedTc.set(best.id, (usedTc.get(best.id) || 0) + 1);
      else y += 140;

      nodes.push({
        id: kid, type: 'kernel',
        position: { x: kernelX, y: nodeY },
        data: { variant, host: trunc(host, 28), reason: trunc(kd.reason || '', 40) },
      });

      const srcId = best ? best.id : prevId;
      if (srcId) {
        edges.push({
          id: `ek-${srcId}-${kid}`,
          source: srcId, target: kid,
          sourceHandle: 'right',
          type: 'smoothstep',
          animated: variant === 'blocked',
          style: {
            stroke:          variant === 'blocked' ? '#ff4d5e' : '#3cd784',
            strokeWidth:     variant === 'blocked' ? 3 : 1.5,
            strokeDasharray: variant === 'blocked' ? '6 3' : undefined,
          },
        });
      }

      if (variant === 'blocked' && best) {
        nodes.push({
          id: `ann-${ke._id}`, type: 'annotation',
          position: { x: kernelX + 20, y: nodeY - 30 },
          data: { variant: 'danger', icon: '⚠', text: 'Prompt injection detected' },
        });
      }
    }

    // ── Safe annotation badges ────────────────────────────────────────────────
    for (const ke of kernelList) {
      if (ke.type === 'connect_blocked') continue;
      let matchedTc = null;
      for (let i = toolCallNodes.length - 1; i >= 0; i--) {
        const tc = toolCallNodes[i];
        const dt = ke.ts - tc.ts;
        if (dt >= 0 && dt <= MATCH_WIN) { matchedTc = tc; break; }
      }
      if (matchedTc && !blockedToolIds.has(matchedTc.id)) {
        nodes.push({
          id: `ann-safe-${ke._id}`, type: 'annotation',
          position: { x: kernelX + 20, y: matchedTc.y + 15 - 30 },
          data: { variant: 'safe', icon: '✓', text: 'Allowed by policy' },
        });
      }
    }
  });

  return { nodes, edges };
}

// ─── Session summary stats ────────────────────────────────────────────────────
function computeSessionStats(llmEvents, kernelEvents) {
  const filtered = llmEvents.filter((e) => e.type !== 'stdout');
  if (filtered.length === 0) return null;

  const firstTs = filtered[0]?.ts;
  const lastTs  = filtered[filtered.length - 1]?.ts;
  const duration = (firstTs != null && lastTs != null) ? lastTs - firstTs : null;

  let steps = 0, requests = 0, blocked = 0;
  for (const e of llmEvents) {
    if (e.type === 'user_input' || e.type === 'tool_call' || e.type === 'agent_output') steps++;
    if (e.type === 'tool_call') requests++;
  }
  for (const e of kernelEvents) {
    if (e.type === 'connect_blocked') blocked++;
  }
  return { duration, steps, requests, blocked };
}

function SessionSummary({ stats }) {
  if (!stats) return null;
  const dur = stats.duration != null
    ? (stats.duration < 10 ? `${stats.duration.toFixed(1)}s` : `${Math.round(stats.duration)}s`)
    : '—';
  return (
    <div className="wf-summary">
      <span className="wf-summary__item">
        <span className="wf-summary__label">Duration</span>
        <span className="wf-summary__value">{dur}</span>
      </span>
      <span className="wf-summary__sep">│</span>
      <span className="wf-summary__item">
        <span className="wf-summary__label">Steps</span>
        <span className="wf-summary__value">{stats.steps}</span>
      </span>
      <span className="wf-summary__sep">│</span>
      <span className="wf-summary__item">
        <span className="wf-summary__label">Requests</span>
        <span className="wf-summary__value">{stats.requests}</span>
      </span>
      <span className="wf-summary__sep">│</span>
      <span className="wf-summary__item">
        <span className="wf-summary__label">Blocked</span>
        <span className={`wf-summary__value${stats.blocked > 0 ? ' wf-summary__value--danger' : ''}`}>
          {stats.blocked}
        </span>
      </span>
    </div>
  );
}

// ─── Exported component ───────────────────────────────────────────────────────
export default function UnifiedFlowLayer({ llmEvents, kernelEvents }) {
  const { nodes, edges } = useMemo(
    () => convertEventsToGraph(llmEvents, kernelEvents),
    [llmEvents, kernelEvents],
  );

  const stats = useMemo(
    () => computeSessionStats(llmEvents, kernelEvents),
    [llmEvents, kernelEvents],
  );

  const [following, setFollowing]   = useState(true);
  const userPannedRef               = useRef(false);
  const containerRef                = useRef(null);

  const handleMoveStart = useCallback((event) => {
    if (event) userPannedRef.current = true;
    else       userPannedRef.current = false;
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
        <span className="wf-empty__sub">The workflow will appear here as events arrive.</span>
      </div>
    );
  }

  return (
    <>
      <SessionSummary stats={stats} />
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