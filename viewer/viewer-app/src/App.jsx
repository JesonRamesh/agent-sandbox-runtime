import { useEffect, useMemo, useRef, useState } from 'react';
import './App.css';
import Header from './components/Header.jsx';
import AgentTabs from './components/AgentTabs.jsx';
import StatsRow from './components/StatsRow.jsx';
import LLMPanel from './components/LLMPanel.jsx';
import KernelPanel from './components/KernelPanel.jsx';
import EventDetail from './components/EventDetail.jsx';
import ScenarioRunner from './components/ScenarioRunner.jsx';

const WS_URL = `ws://${location.hostname}:${location.port || '8765'}`;
const RECONNECT_DELAY_MS = 3000;
const MAX_EVENTS = 500;

const LLM_TYPES = new Set(['stdout', 'tool_call', 'stopped', 'crashed']);

// Pillar × verdict types emitted by the bridge transform. Keep this in
// lockstep with viewer/server/transform.js (UI_KERNEL_TYPES) — the
// bridge's unit tests assert the exact set.
const KERNEL_TYPES = new Set([
  'net_allowed',  'net_blocked',
  'file_allowed', 'file_blocked',
  'exec_allowed', 'exec_blocked',
  'cred_allowed', 'cred_blocked',
  // Legacy aliases — accepted so a mock stream that still emits the old
  // schema doesn't get silently dropped during the migration window.
  'connect_attempt', 'connect_allowed', 'connect_blocked',
]);

const BANNER_REVEAL_DELAY_MS = 300;
const BANNER_AUTO_DISMISS_MS = 5000;
const MATCH_WINDOW_SEC = 10;

function findInjectionTarget(blocked, llmEvents) {
  // Best-effort link from a blocked kernel row to the tool_call that drove
  // it. Only meaningful when the orchestrator is feeding LLM events; with
  // just bridge-driven kernel events it will simply return null.
  const target = blocked.data?.target || blocked.data?.hostname;
  let fallbackId = null;
  for (let i = llmEvents.length - 1; i >= 0; i--) {
    const e = llmEvents[i];
    if (e.agent !== blocked.agent) continue;
    const dt = Math.abs(blocked.ts - e.ts);
    if (dt > MATCH_WINDOW_SEC) break;
    if (e.type !== 'tool_call') continue;
    const url = (e.data?.args?.url || '').toString();
    if (target && url.includes(target)) return e._id;
    if (fallbackId === null) fallbackId = e._id;
  }
  return fallbackId;
}

export default function App() {
  const [wsStatus, setWsStatus] = useState('disconnected');
  const [llmEvents, setLlmEvents] = useState([]);
  const [kernelEvents, setKernelEvents] = useState([]);
  const [activeAgent, setActiveAgent] = useState(null);
  const [uptime, setUptime] = useState(0);

  const [selectedEventId, setSelectedEventId] = useState(null);

  const [injectionAlert, setInjectionAlert] = useState(null);
  const [injectionTargets, setInjectionTargets] = useState(() => new Set());
  const [blockedPulseKey, setBlockedPulseKey] = useState(0);

  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const cancelledRef = useRef(false);
  const eventIdRef = useRef(0);
  const handledBlockedRef = useRef(new Set());
  const bannerTimersRef = useRef([]);

  const clearBannerTimers = () => {
    for (const t of bannerTimersRef.current) clearTimeout(t);
    bannerTimersRef.current = [];
  };

  useEffect(() => {
    cancelledRef.current = false;

    const connect = () => {
      if (cancelledRef.current) return;
      const ws = new WebSocket(WS_URL);
      socketRef.current = ws;

      ws.onopen = () => {
        ws.send(JSON.stringify({ role: 'viewer' }));
        setWsStatus('connected');
      };

      ws.onmessage = (msg) => {
        let event;
        try {
          event = JSON.parse(msg.data);
        } catch {
          console.warn('viewer: dropped malformed message');
          return;
        }
        if (!event || typeof event.type !== 'string') return;
        const stamped = { ...event, _id: ++eventIdRef.current };
        if (LLM_TYPES.has(stamped.type)) {
          setLlmEvents((prev) => [...prev, stamped].slice(-MAX_EVENTS));
        } else if (KERNEL_TYPES.has(stamped.type)) {
          setKernelEvents((prev) => [...prev, stamped].slice(-MAX_EVENTS));
        } else {
          console.warn('viewer: unknown event type', stamped.type);
        }
      };

      ws.onerror = () => { /* close handler will reconnect */ };

      ws.onclose = () => {
        setWsStatus('disconnected');
        socketRef.current = null;
        if (cancelledRef.current) return;
        reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
      };
    };

    connect();

    return () => {
      cancelledRef.current = true;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (socketRef.current) {
        socketRef.current.onclose = null;
        socketRef.current.close();
        socketRef.current = null;
      }
      clearBannerTimers();
    };
  }, []);

  useEffect(() => {
    const start = Date.now();
    const id = setInterval(() => {
      setUptime(Math.floor((Date.now() - start) / 1000));
    }, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (kernelEvents.length === 0) return;
    const handled = handledBlockedRef.current;
    let toAdd = null;
    let lastAlert = null;
    for (const ke of kernelEvents) {
      if (!ke.type.endsWith('_blocked')) continue;
      if (handled.has(ke._id)) continue;
      handled.add(ke._id);
      const matchedId = findInjectionTarget(ke, llmEvents);
      if (matchedId !== null) {
        if (!toAdd) toAdd = new Set();
        toAdd.add(matchedId);
      }
      lastAlert = {
        kernelId: ke._id,
        toolCallId: matchedId,
        hostname: ke.data?.target || ke.data?.hostname || ke.data?.dst_ip || 'unknown',
        reason: ke.data?.reason || '',
      };
    }
    if (!lastAlert) return;
    if (toAdd) {
      setInjectionTargets((prev) => {
        const next = new Set(prev);
        for (const id of toAdd) next.add(id);
        return next;
      });
    }
    setBlockedPulseKey((k) => k + 1);
    clearBannerTimers();
    const reveal = setTimeout(() => setInjectionAlert(lastAlert), BANNER_REVEAL_DELAY_MS);
    const dismiss = setTimeout(
      () => setInjectionAlert((cur) => (cur && cur.kernelId === lastAlert.kernelId ? null : cur)),
      BANNER_REVEAL_DELAY_MS + BANNER_AUTO_DISMISS_MS,
    );
    bannerTimersRef.current.push(reveal, dismiss);
  }, [kernelEvents, llmEvents]);

  const dismissAlert = () => {
    clearBannerTimers();
    setInjectionAlert(null);
  };

  // Clear every piece of dashboard state derived from incoming events. The
  // WebSocket connection itself stays open; uptime keeps counting (it's a
  // measure of the dashboard session, not the event stream). Future events
  // start a fresh history.
  const handleReset = () => {
    clearBannerTimers();
    setLlmEvents([]);
    setKernelEvents([]);
    setSelectedEventId(null);
    setActiveAgent(null);
    setInjectionAlert(null);
    setInjectionTargets(new Set());
    setBlockedPulseKey(0);
    handledBlockedRef.current = new Set();
    // eventIdRef intentionally NOT reset — keeping it monotonic across
    // resets means React keys never collide with stale events still in
    // any component's local state during the same render tick.
  };

  const agents = useMemo(() => {
    const names = new Set();
    for (const e of llmEvents) names.add(e.agent);
    for (const e of kernelEvents) names.add(e.agent);
    return Array.from(names);
  }, [llmEvents, kernelEvents]);

  useEffect(() => {
    if (activeAgent === null && agents.length > 0) {
      setActiveAgent(agents[0]);
    }
  }, [agents, activeAgent]);

  // Per-pillar counters. Walk kernelEvents once and bucket by type.
  const stats = useMemo(() => {
    const s = {
      toolCalls: 0,
      uptime,
      netAllowed: 0,  netBlocked: 0,
      fileAllowed: 0, fileBlocked: 0,
      execAllowed: 0, execBlocked: 0,
      credAllowed: 0, credBlocked: 0,
    };
    for (const e of llmEvents) if (e.type === 'tool_call') s.toolCalls += 1;
    for (const e of kernelEvents) {
      switch (e.type) {
        case 'net_allowed':  s.netAllowed  += 1; break;
        case 'net_blocked':  s.netBlocked  += 1; break;
        case 'file_allowed': s.fileAllowed += 1; break;
        case 'file_blocked': s.fileBlocked += 1; break;
        case 'exec_allowed': s.execAllowed += 1; break;
        case 'exec_blocked': s.execBlocked += 1; break;
        case 'cred_allowed': s.credAllowed += 1; break;
        case 'cred_blocked': s.credBlocked += 1; break;
        // Legacy fall-back so old streams still bump network counters.
        case 'connect_allowed': s.netAllowed += 1; break;
        case 'connect_blocked': s.netBlocked += 1; break;
        default: break;
      }
    }
    return s;
  }, [llmEvents, kernelEvents, uptime]);

  const filteredLlm = activeAgent
    ? llmEvents.filter((e) => e.agent === activeAgent)
    : llmEvents;
  const filteredKernel = activeAgent
    ? kernelEvents.filter((e) => e.agent === activeAgent)
    : kernelEvents;

  const selectedEvent = useMemo(
    () => kernelEvents.find((e) => e._id === selectedEventId) || null,
    [kernelEvents, selectedEventId],
  );

  return (
    <div className="app">
      <Header
        wsStatus={wsStatus}
        onReset={handleReset}
        eventCount={llmEvents.length + kernelEvents.length}
      />
      <ScenarioRunner />
      <AgentTabs agents={agents} activeAgent={activeAgent} onSelectAgent={setActiveAgent} />
      <StatsRow stats={stats} blockedPulseKey={blockedPulseKey} />
      <div className="app__panels">
        <LLMPanel
          events={filteredLlm}
          alert={injectionAlert}
          injectionTargets={injectionTargets}
          onDismissAlert={dismissAlert}
        />
        <KernelPanel
          events={filteredKernel}
          selectedEventId={selectedEventId}
          onSelectEvent={setSelectedEventId}
        />
      </div>
      {selectedEvent && (
        <div className="app__detail-overlay">
          <EventDetail event={selectedEvent} onClose={() => setSelectedEventId(null)} />
        </div>
      )}
    </div>
  );
}
