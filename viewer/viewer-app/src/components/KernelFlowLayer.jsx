import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactFlow, {
  Background, Controls, Handle, Position,
  ReactFlowProvider, useReactFlow,
} from 'reactflow';
import 'reactflow/dist/style.css';

// ─── Layout ───────────────────────────────────────────────────────────────────
const ATTEMPT_X  = 60;   // left column — connect_attempt nodes
const VERDICT_X  = 380;  // right column — verdict (allowed/blocked) nodes
const NODE_GAP   = 160;
const START_Y    = 50;
const CARD_W     = 260;
const MATCH_WIN  = 10;   // seconds

// ─── Helpers ──────────────────────────────────────────────────────────────────
function trunc(str, n) {
  if (!str) return '';
  str = String(str);
  return str.length > n ? str.slice(0, n) + '\u2026' : str;
}

function formatDelta(seconds) {
  if (seconds == null || isNaN(seconds)) return null;
  if (seconds < 0.01) return '<0.01s';
  if (seconds < 1)    return `${(seconds * 1000).toFixed(0)}ms`;
  if (seconds < 10)   return `${seconds.toFixed(1)}s`;
  return `${Math.round(seconds)}s`;
}

function formatTime(ts) {
  if (!ts && ts !== 0) return '\u2014';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false }) +
    '.' + String(d.getMilliseconds()).padStart(3, '0');
}

// ─── Node renderers ───────────────────────────────────────────────────────────

// Attempt node — connect_attempt (left column)
function KflAttemptNode({ data }) {
  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div className="kfl-attempt">
        <div className="kfl-attempt__header">
          <span className="kfl-attempt__icon">⤷</span>
          <span className="kfl-attempt__label">Connection attempt</span>
          <span className="kfl-attempt__time">{data.time}</span>
        </div>
        <div className="kfl-attempt__host">{data.host}</div>
        {data.dst && <div className="kfl-attempt__dst">{data.dst}</div>}
      </div>
      <Handle type="source" position={Position.Bottom} />
      <Handle type="source" position={Position.Right} id="right" />
    </>
  );
}

// Verdict node — connect_allowed / connect_blocked (right column)
function KflVerdictNode({ data }) {
  const blocked = data.variant === 'blocked';
  return (
    <>
      <Handle type="target" position={Position.Left} />
      <div className={`kfl-verdict kfl-verdict--${data.variant}`}>
        <div className="kfl-verdict__header">
          <span className="kfl-verdict__icon">{blocked ? '🛡' : '✓'}</span>
          <span className="kfl-verdict__label">
            {blocked ? 'Blocked by kernel' : 'Permitted by policy'}
          </span>
        </div>
        <div className="kfl-verdict__host">{data.host}</div>
        <div className="kfl-verdict__reason">
          {blocked
            ? (data.reason ? `Policy: ${data.reason}` : 'No matching allow rule')
            : (data.reason ? `Rule: ${data.reason}` : 'Matches allowed_hosts')}
        </div>
        {data.time && <div className="kfl-verdict__time">{data.time}</div>}
      </div>
    </>
  );
}

// Orphan verdict node — verdict with no matching attempt (right column, standalone)
function KflOrphanVerdictNode({ data }) {
  const blocked = data.variant === 'blocked';
  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div className={`kfl-verdict kfl-verdict--${data.variant}`}>
        <div className="kfl-verdict__header">
          <span className="kfl-verdict__icon">{blocked ? '🛡' : '✓'}</span>
          <span className="kfl-verdict__label">
            {blocked ? 'Blocked by kernel' : 'Permitted by policy'}
          </span>
        </div>
        <div className="kfl-verdict__host">{data.host}</div>
        <div className="kfl-verdict__reason">
          {blocked
            ? (data.reason ? `Policy: ${data.reason}` : 'No matching allow rule')
            : (data.reason ? `Rule: ${data.reason}` : 'Matches allowed_hosts')}
        </div>
        {data.time && <div className="kfl-verdict__time">{data.time}</div>}
      </div>
      <Handle type="source" position={Position.Bottom} />
    </>
  );
}

// Policy badge — floats above a blocked verdict as context
function KflPolicyNode({ data }) {
  return (
    <div className={`kfl-policy kfl-policy--${data.variant}`}>
      <span className="kfl-policy__icon">{data.icon}</span>
      <span className="kfl-policy__text">{data.text}</span>
    </div>
  );
}

// Session bookend circles
function KflCircleNode({ data }) {
  return (
    <>
      {!data.isStart    && <Handle type="target" position={Position.Top} />}
      <div className={`kfl-circle kfl-circle--${data.variant}`}>
        <span className="kfl-circle__icon">{data.icon}</span>
        <span className="kfl-circle__label">{data.label}</span>
        {data.sub && <span className="kfl-circle__sub">{data.sub}</span>}
      </div>
      {!data.isTerminal && <Handle type="source" position={Position.Bottom} />}
    </>
  );
}

const nodeTypes = {
  'kfl-attempt':        KflAttemptNode,
  'kfl-verdict':        KflVerdictNode,
  'kfl-orphan-verdict': KflOrphanVerdictNode,
  'kfl-policy':         KflPolicyNode,
  'kfl-circle':         KflCircleNode,
};

// ─── Auto-follow ──────────────────────────────────────────────────────────────
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
    const nW = bottom.style?.width ? parseInt(bottom.style.width) : CARD_W;
    const nH = bottom.type === 'kfl-circle' ? 120 : 90;
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

// ─── Graph builder ────────────────────────────────────────────────────────────
function buildKernelGraph(llmEvents, kernelEvents) {
  // ── Group every event by session_id ────────────────────────────────────────
  // session_id is stamped on every mock event; fall back to agent name so real
  // daemon events (which may omit session_id) still group sensibly.
  const sessionMap = new Map(); // session_id → { llm: [], kernel: [] }

  const getSession = (sid) => {
    if (!sessionMap.has(sid)) sessionMap.set(sid, { llm: [], kernel: [] });
    return sessionMap.get(sid);
  };

  for (const e of llmEvents) {
    const sid = e.session_id || e.agent || 'unknown';
    getSession(sid).llm.push(e);
  }
  for (const e of kernelEvents) {
    const sid = e.session_id || e.agent || 'unknown';
    getSession(sid).kernel.push(e);
  }



  // Sort sessions chronologically — oldest first so the graph reads top→bottom
  const sessions = [...sessionMap.entries()].sort((a, b) => {



    const tsA = (a[1].llm[0] || a[1].kernel[0])?.ts ?? 0;
    const tsB = (b[1].llm[0] || b[1].kernel[0])?.ts ?? 0;
    return tsA - tsB;
  });




  const SESSION_GAP = 60; // extra vertical space between sessions
  const nodes = [];
  const edges = [];


  // Running Y offset shared across all sessions so they stack vertically
  let globalY = START_Y;

  sessions.forEach(([sid, { llm: lEvents, kernel: kEvents }]) => {
    const offsetX  = 0;
    const attemptX = offsetX + ATTEMPT_X;
    const verdictX = offsetX + VERDICT_X;
    const circleX  = offsetX + ATTEMPT_X + (CARD_W - 120) / 2;

    // Derive agent label from first event
    const agent = lEvents[0]?.agent || kEvents[0]?.agent || sid;

    // Separate kernel event types
    const attempts = kEvents.filter((e) => e.type === 'connect_attempt');
    const verdicts = kEvents.filter((e) =>
      e.type === 'connect_allowed' || e.type === 'connect_blocked'
    );

    // Per-session bookends from the LLM stream
    const sessionStart = lEvents.find((e) => e.type === 'session_start');
    const sessionEnd   = lEvents.find((e) => e.type === 'stopped' || e.type === 'crashed');


    let y      = globalY;
    let prevId = null;

    // ── Session start bookend ─────────────────────────────────────────────────
    if (sessionStart) {
      const id = `kfl-start-${sessionStart._id}`;
      const d  = sessionStart.data || {};
      nodes.push({
        id, type: 'kfl-circle',
        position: { x: circleX, y },
        data: {
          variant: 'start', isStart: true,
          icon: '▶', label: 'Session Start',
          sub: d.launch_mode ? `${agent} · ${d.launch_mode}` : agent,
        },
      });
      prevId = id;
      y += 150;
    }

    // ── Match each attempt to its nearest following verdict ───────────────────
    const usedVerdicts = new Set();
    const pairs = [];

    for (const att of attempts) {
      let best = null, bestDt = Infinity;
      for (const verd of verdicts) {
        if (usedVerdicts.has(verd._id)) continue;
        const dt = verd.ts - att.ts;
        if (dt >= 0 && dt <= MATCH_WIN && dt < bestDt) { best = verd; bestDt = dt; }
      }
      pairs.push({ attempt: att, verdict: best });
      if (best) usedVerdicts.add(best._id);
    }

    // Verdicts with no matching attempt
    const orphanVerdicts = verdicts.filter((v) => !usedVerdicts.has(v._id));
    if (attempts.length === 0) orphanVerdicts.push(...verdicts);

    pairs.sort((a, b) => (a.attempt.ts || 0) - (b.attempt.ts || 0));
    orphanVerdicts.sort((a, b) => (a.ts || 0) - (b.ts || 0));

    // ── Render attempt + verdict pairs ───────────────────────────────────────
    for (const { attempt: att, verdict: verd } of pairs) {
      const attId = `kfl-att-${att._id}`;
      const attD  = att.data || {};
      const host  = attD.hostname || attD.dst_ip || '?';
      const dst   = attD.dst_ip ? `${attD.dst_ip}:${attD.dst_port || '?'}` : null;

      nodes.push({
        id: attId, type: 'kfl-attempt',
        position: { x: attemptX, y },
        data: { host: trunc(host, 30), dst: dst ? trunc(dst, 28) : null, time: formatTime(att.ts) },
        style: { width: `${CARD_W}px` },
      });

      if (prevId) {
        edges.push({
          id: `kfl-e-${prevId}-${attId}`, source: prevId, target: attId,
          type: 'smoothstep', style: { stroke: '#2a3550', strokeWidth: 2 },
        });
      }
      prevId = attId;

      if (verd) {
        const verdId  = `kfl-verd-${verd._id}`;
        const verdD   = verd.data || {};
        const blocked = verd.type === 'connect_blocked';
        const verdHost = verdD.hostname || verdD.dst_ip || '?';
        const dt = (verd.ts != null && att.ts != null) ? verd.ts - att.ts : null;

        nodes.push({
          id: verdId, type: 'kfl-verdict',
          position: { x: verdictX, y: y + 10 },
          data: {
            variant: blocked ? 'blocked' : 'allowed',
            host:    trunc(verdHost, 26),
            reason:  trunc(verdD.reason || '', 40),
            time:    dt !== null ? `verdict in ${formatDelta(dt)}` : formatTime(verd.ts),
          },
          style: { width: `${CARD_W}px` },
        });

        edges.push({
          id: `kfl-h-${attId}-${verdId}`,
          source: attId, target: verdId, sourceHandle: 'right',
          type: 'smoothstep', animated: blocked,
          style: {
            stroke:          blocked ? '#ff4d5e' : '#3cd784',
            strokeWidth:     blocked ? 2.5 : 1.5,
            strokeDasharray: blocked ? '6 3' : undefined,
          },
        });

        nodes.push({
          id: `kfl-badge-${verd._id}`, type: 'kfl-policy',
          position: { x: verdictX + 10, y: y - 22 },
          data: {
            variant: blocked ? 'danger' : 'safe',
            icon:    blocked ? '⚠' : '✓',
            text:    blocked ? 'Prompt injection detected' : 'Allowed by policy',
          },
        });
      }

      y += NODE_GAP;
    }

    // ── Orphan verdicts ───────────────────────────────────────────────────────
    for (const verd of orphanVerdicts) {
      const verdId  = `kfl-orphan-${verd._id}`;
      const verdD   = verd.data || {};
      const blocked = verd.type === 'connect_blocked';
      const host    = verdD.hostname || verdD.dst_ip || '?';

      nodes.push({
        id: verdId, type: 'kfl-orphan-verdict',
        position: { x: attemptX, y },
        data: {
          variant: blocked ? 'blocked' : 'allowed',
          host:    trunc(host, 26),
          reason:  trunc(verdD.reason || '', 40),
          time:    formatTime(verd.ts),
        },
        style: { width: `${CARD_W}px` },
      });

      if (prevId) {
        edges.push({
          id: `kfl-e-${prevId}-${verdId}`, source: prevId, target: verdId,
          type: 'smoothstep', animated: blocked,
          style: { stroke: blocked ? '#ff4d5e' : '#2a3550', strokeWidth: blocked ? 2.5 : 2 },
        });
      }
      prevId = verdId;
      y += NODE_GAP;
    }

    // ── Session end bookend ───────────────────────────────────────────────────
    if (sessionEnd) {
      const id      = `kfl-end-${sessionEnd._id}`;
      const crashed = sessionEnd.type === 'crashed';
      const d       = sessionEnd.data || {};
      nodes.push({
        id, type: 'kfl-circle',
        position: { x: circleX, y },
        data: {
          variant: crashed ? 'crashed' : 'complete', isTerminal: true,
          icon:    crashed ? '✕' : '✓',
          label:   crashed ? 'Crashed' : 'Done',
          sub: crashed
            ? `exit ${d.exit_code ?? '?'}`
            : (d.exit_code === 0 || d.exit_code == null ? 'finished successfully' : `exit ${d.exit_code}`),
        },
      });
      if (prevId) {
        edges.push({
          id: `kfl-e-${prevId}-${id}`, source: prevId, target: id,
          type: 'smoothstep', style: { stroke: '#2a3550', strokeWidth: 2 },
        });
      }
      y += 150; // circle node height
    }

    // Advance global Y so the next session starts below this one
    globalY = y + SESSION_GAP;
  });

  return { nodes, edges };
}

// ─── Summary ribbon ───────────────────────────────────────────────────────────
function computeKernelStats(kernelEvents) {
  let attempts = 0, allowed = 0, blocked = 0;
  const firstTs = kernelEvents[0]?.ts;
  const lastTs  = kernelEvents[kernelEvents.length - 1]?.ts;

  for (const e of kernelEvents) {
    if (e.type === 'connect_attempt') attempts++;
    if (e.type === 'connect_allowed') allowed++;
    if (e.type === 'connect_blocked') blocked++;
  }

  const total      = allowed + blocked;
  const blockRate  = total > 0 ? Math.round((blocked / total) * 100) : null;
  const duration   = (firstTs != null && lastTs != null) ? lastTs - firstTs : null;

  return { attempts, allowed, blocked, blockRate, duration };
}

function KernelSummary({ stats }) {
  if (!stats || (stats.attempts === 0 && stats.allowed === 0 && stats.blocked === 0)) return null;
  const dur = stats.duration != null
    ? (stats.duration < 10 ? `${stats.duration.toFixed(1)}s` : `${Math.round(stats.duration)}s`)
    : '\u2014';
  return (
    <div className="kfl-summary">
      <span className="kfl-summary__item">
        <span className="kfl-summary__label">Duration</span>
        <span className="kfl-summary__value">{dur}</span>
      </span>
      <span className="kfl-summary__sep">│</span>
      <span className="kfl-summary__item">
        <span className="kfl-summary__label">Attempts</span>
        <span className="kfl-summary__value">{stats.attempts}</span>
      </span>
      <span className="kfl-summary__sep">│</span>
      <span className="kfl-summary__item">
        <span className="kfl-summary__label">Allowed</span>
        <span className="kfl-summary__value kfl-summary__value--good">{stats.allowed}</span>
      </span>
      <span className="kfl-summary__sep">│</span>
      <span className="kfl-summary__item">
        <span className="kfl-summary__label">Blocked</span>
        <span className={`kfl-summary__value${stats.blocked > 0 ? ' kfl-summary__value--danger' : ''}`}>
          {stats.blocked}
        </span>
      </span>
      {stats.blockRate !== null && (
        <>
          <span className="kfl-summary__sep">│</span>
          <span className="kfl-summary__item">
            <span className="kfl-summary__label">Block rate</span>
            <span className={`kfl-summary__value${stats.blockRate > 0 ? ' kfl-summary__value--danger' : ' kfl-summary__value--good'}`}>
              {stats.blockRate}%
            </span>
          </span>
        </>
      )}
    </div>
  );
}

// ─── Exported component ───────────────────────────────────────────────────────
export default function KernelFlowLayer({ llmEvents, kernelEvents }) {
  const { nodes, edges } = useMemo(
    () => buildKernelGraph(llmEvents, kernelEvents),
    [llmEvents, kernelEvents],
  );

  const stats = useMemo(
    () => computeKernelStats(kernelEvents),
    [kernelEvents],
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
        <span className="wf-empty__title">Waiting for kernel events…</span>
        <span className="wf-empty__sub">Connection attempts and verdicts will appear here.</span>
      </div>
    );
  }

  return (
    <>
      <KernelSummary stats={stats} />
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