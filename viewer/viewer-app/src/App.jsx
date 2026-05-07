import { useEffect, useMemo, useRef, useState } from 'react';
import './App.css';
import Header from './components/Header.jsx';
import Sidebar from './components/Sidebar.jsx';
import StatRings from './components/StatRings.jsx';
import LLMPanel from './components/LLMPanel.jsx';
import KernelPanel from './components/KernelPanel.jsx';
import ThreatGauge from './components/ThreatGauge.jsx';
import MiniFlow from './components/MiniFlow.jsx';
import ConnectionTimeline from './components/ConnectionTimeline.jsx';
import WorkflowGraph from './components/WorkflowGraph.jsx';
import './components/WorkflowGraph.css';

const WS_URL = 'ws://localhost:8765';
const RECONNECT_DELAY_MS = 3000;
const MAX_EVENTS = 500;

const LLM_TYPES = new Set([
  'stdout', 'tool_call', 'stopped', 'crashed',
  'session_start', 'user_input', 'tool_result', 'agent_output',
]);
const KERNEL_TYPES = new Set(['connect_attempt', 'connect_allowed', 'connect_blocked']);

// Banner reveal is delayed slightly after the kernel row flashes so the eye
// follows the chain of cause from RIGHT panel → LEFT banner.
const BANNER_REVEAL_DELAY_MS = 300;
const BANNER_AUTO_DISMISS_MS = 5000;

// How far back (in seconds) to look for a tool_call that matches a blocked
// kernel event. Longer than the mock cadence (~1.5s) so we still match even
// if the streams drift slightly.
const MATCH_WINDOW_SEC = 10;

// Walk the LLM history backwards to find the tool_call that best explains
// this blocked connection. Prefer URL-substring match; fall back to nearest
// tool_call in the time window.
function findInjectionTarget(blocked, llmEvents) {
  const target = blocked.data?.hostname;
  let fallbackId = null;
  for (let i = llmEvents.length - 1; i >= 0; i--) {
    const e = llmEvents[i];
    if (e.agent !== blocked.agent) continue;
    const dt = Math.abs((blocked.ts - e.ts));
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

  // Cross-panel alert state — owned here so all three children can react.
  const [injectionAlert, setInjectionAlert] = useState(null);
  const [injectionTargets, setInjectionTargets] = useState(() => new Set());
  const [blockedPulseKey, setBlockedPulseKey] = useState(0);
  const [latestAnalysis, setLatestAnalysis] = useState(null);
  const [lastAnalysisTs, setLastAnalysisTs] = useState(null);
  const [activeTab, setActiveTab] = useState('events');

  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const cancelledRef = useRef(false);

  // Monotonic id counter for stable React keys + the injectionTargets Set.
  const eventIdRef = useRef(0);

  // Track which connect_blocked events we've already reacted to so the
  // matching effect doesn't re-fire on unrelated re-renders.
  const handledBlockedRef = useRef(new Set());

  // Pending banner timers — cleared on unmount + on dismiss.
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
        } else if (stamped.type === 'security_analysis') {
          setLatestAnalysis(stamped.data);
          setLastAnalysisTs(stamped.ts);
        } else {
          console.warn('viewer: unknown event type', stamped.type);
        }
      };

      ws.onerror = () => {
        // onclose will fire next; reconnect is scheduled there.
      };

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

  // React to new connect_blocked events: link to a tool_call, schedule the
  // banner reveal + auto-dismiss, and bump the stats pulse key.
  useEffect(() => {
    if (kernelEvents.length === 0) return;
    const handled = handledBlockedRef.current;
    let toAdd = null; // ids to add to injectionTargets after the loop
    let lastAlert = null;

    for (const ke of kernelEvents) {
      if (ke.type !== 'connect_blocked') continue;
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
        hostname: ke.data?.hostname || ke.data?.dst_ip || 'unknown',
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

    // Stats pulse fires immediately — the counter changes the same tick.
    setBlockedPulseKey((k) => k + 1);

    // Banner reveal is staged 300ms after the kernel row appears.
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

  const stats = useMemo(() => {
    let toolCalls = 0;
    for (const e of llmEvents) if (e.type === 'tool_call') toolCalls += 1;
    let allowed = 0;
    let blocked = 0;
    for (const e of kernelEvents) {
      if (e.type === 'connect_allowed') allowed += 1;
      else if (e.type === 'connect_blocked') blocked += 1;
    }
    return { toolCalls, allowed, blocked, uptime };
  }, [llmEvents, kernelEvents, uptime]);

  const filteredLlm = activeAgent
    ? llmEvents.filter((e) => e.agent === activeAgent)
    : llmEvents;
  const filteredKernel = activeAgent
    ? kernelEvents.filter((e) => e.agent === activeAgent)
    : kernelEvents;

  return (
    <div className="app">
      {/* Top header bar — full width */}
      <Header wsStatus={wsStatus} llmEvents={llmEvents} kernelEvents={kernelEvents} />

      {/* Main body: sidebar + content */}
      <div className="app__body">
        <Sidebar
          agents={agents}
          activeAgent={activeAgent}
          onSelectAgent={setActiveAgent}
          llmEvents={llmEvents}
          kernelEvents={kernelEvents}
          stats={stats}
          wsStatus={wsStatus}
          activeTab={activeTab}
          onSelectTab={setActiveTab}
        />

        <div className={`app__main${activeTab === 'workflow' ? ' app__main--workflow' : ''}`}>
          {/* Animated ring stats — hidden on workflow tab */}
          {activeTab === 'events' && <StatRings stats={stats} blockedPulseKey={blockedPulseKey} />}

          {/* Event panels or workflow graph */}
          {activeTab === 'events' ? (
            <>
            <MiniFlow
              llmEvents={filteredLlm}
              kernelEvents={filteredKernel}
              injectionTargets={injectionTargets}
            />
            <div className="app__panels">
              <LLMPanel
                events={filteredLlm}
                alert={injectionAlert}
                injectionTargets={injectionTargets}
                onDismissAlert={dismissAlert}
              />
              <KernelPanel events={filteredKernel} />
            </div>
            </>  
          ) : (
            <div className="app__workflow">
              <WorkflowGraph llmEvents={filteredLlm} kernelEvents={filteredKernel} />
            </div>
          )}

          {/* Connection timeline + threat gauge — events tab only */}
          {activeTab === 'events' && (
            <>
              <ConnectionTimeline kernelEvents={filteredKernel} />
              <ThreatGauge analysis={latestAnalysis} lastTs={lastAnalysisTs} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
