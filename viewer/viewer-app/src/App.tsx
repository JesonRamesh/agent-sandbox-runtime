import { useEffect, useMemo, useRef, useState } from 'react';
import './App.css';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import StatRings from './components/StatRings';
import LLMPanel from './components/LLMPanel';
import KernelPanel from './components/KernelPanel';
import ThreatGauge from './components/ThreatGauge';
import MiniFlow from './components/MiniFlow';
import ConnectionTimeline from './components/ConnectionTimeline';
import WorkflowGraph from './components/WorkflowGraph';
import './components/WorkflowGraph.css';
import PolicyView from './components/PolicyView';
import LLMAgentLauncher from './components/LLMAgentLauncher';
import { fetchPolicies } from './api/daemonApi';
import { MOCK_POLICIES } from './api/mockPolicies';
import type { LLMEvent, KernelEvent, SecurityAnalysis } from './types/events';

const WS_URL = 'ws://localhost:8765';
const RECONNECT_DELAY_MS = 3000;
const MAX_EVENTS = 500;

const LLM_TYPES = new Set([
  'stdout', 'tool_call', 'stopped', 'crashed',
  'session_start', 'user_input', 'tool_result', 'agent_output',
]);
// Kernel event type allow-list. Includes both:
//   * legacy `connect_*` types (used by the original mock emitter and any
//     older sender)
//   * pillar-aware `<pillar>_<verdict>` types emitted by viewer/server/
//     transform.js when the daemon's bridge is connected (net/file/exec/
//     cred × allowed/blocked)
// The dashboard's stats logic below treats `*_blocked` as blocked and
// `*_allowed` as allowed, so adding a new pillar in the bridge does not
// require touching this file.
const KERNEL_TYPES = new Set([
  'connect_attempt', 'connect_allowed', 'connect_blocked',
  'net_allowed',  'net_blocked',
  'file_allowed', 'file_blocked',
  'exec_allowed', 'exec_blocked',
  'cred_allowed', 'cred_blocked',
]);

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
function findInjectionTarget(blocked: KernelEvent, llmEvents: LLMEvent[]): number | null {
  const target = blocked.data?.hostname;
  let fallbackId: number | null = null;
  for (let i = llmEvents.length - 1; i >= 0; i--) {
    const e = llmEvents[i];
    if (e.agent !== blocked.agent) continue;
    const dt = Math.abs((blocked.ts - e.ts));
    if (dt > MATCH_WINDOW_SEC) break;
    if (e.type !== 'tool_call') continue;
    const url = ((e.data?.args as any)?.url || '').toString();
    if (target && url.includes(target)) return e._id;
    if (fallbackId === null) fallbackId = e._id;
  }
  return fallbackId;
}

interface InjectionAlert {
  kernelId: number;
  toolCallId: number | null;
  hostname: string;
  reason: string;
}

export default function App() {
  const [wsStatus, setWsStatus] = useState<string>('disconnected');
  const [llmEvents, setLlmEvents] = useState<LLMEvent[]>([]);
  const [kernelEvents, setKernelEvents] = useState<KernelEvent[]>([]);
  const [activeAgent, setActiveAgent] = useState<string | null>(null);
  const [uptime, setUptime] = useState<number>(0);

  // Cross-panel alert state — owned here so all three children can react.
  const [injectionAlert, setInjectionAlert] = useState<InjectionAlert | null>(null);
  const [latestAnalysis, setLatestAnalysis] = useState<SecurityAnalysis | null>(null);
  const [lastAnalysisTs, setLastAnalysisTs] = useState<number | null>(null);
  // 'events' | 'workflow' | 'policies'
  const [activeTab, setActiveTab] = useState<string>('events');

  // Policy count — fetched once on mount so sidebar can show it on all tabs
  const [policyCount, setPolicyCount] = useState<number | null>(null);

  // Load policy count once on mount (falls back to mock length if daemon offline)
  useEffect(() => {
    fetchPolicies()
      .then((data) => setPolicyCount((data || []).length))
      .catch(() => setPolicyCount(MOCK_POLICIES.length));
  }, []);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancelledRef = useRef<boolean>(false);

  // Monotonic id counter for stable React keys + the injectionTargets Set.
  const eventIdRef = useRef<number>(0);

  // Track which connect_blocked events we've already reacted to so the
  // matching effect doesn't re-fire on unrelated re-renders.
  const handledBlockedRef = useRef<Set<number>>(new Set());

  // Pending banner timers — cleared on unmount + on dismiss.
  const bannerTimersRef = useRef<Array<ReturnType<typeof setTimeout>>>([]);
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
        let event: any;
        try {
          event = JSON.parse(msg.data);
        } catch {
          console.warn('viewer: dropped malformed message');
          return;
        }
        if (!event || typeof event.type !== 'string') return;

        const stamped = { ...event, _id: ++eventIdRef.current };

        if (LLM_TYPES.has(stamped.type)) {
          setLlmEvents((prev) => [...prev, stamped as LLMEvent].slice(-MAX_EVENTS));
        } else if (KERNEL_TYPES.has(stamped.type)) {
          setKernelEvents((prev) => [...prev, stamped as KernelEvent].slice(-MAX_EVENTS));
        } else if (stamped.type === 'security_analysis') {
          setLatestAnalysis(stamped.data as SecurityAnalysis);
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

  // `injectionTargets` is derivable from the event streams — `findInjectionTarget`
  // is pure, so we compute it during render rather than accumulating into state
  // (which would require a synchronous setState in an effect).
  const injectionTargets = useMemo<Set<number>>(() => {
    const targets = new Set<number>();
    for (const ke of kernelEvents) {
      if (!ke.type.endsWith('_blocked')) continue;
      const matched = findInjectionTarget(ke, llmEvents);
      if (matched !== null) targets.add(matched);
    }
    return targets;
  }, [kernelEvents, llmEvents]);

  // Counter that bumps once per blocked kernel event — drives the StatRings
  // pulse animation. Derived from kernelEvents so we don't setState in an effect.
  const blockedPulseKey = useMemo<number>(() => {
    let count = 0;
    for (const ke of kernelEvents) {
      if (ke.type.endsWith('_blocked')) count += 1;
    }
    return count;
  }, [kernelEvents]);

  // React to new connect_blocked events: schedule the banner reveal +
  // auto-dismiss and bump the stats pulse key. Target accumulation moved
  // to the useMemo above so this effect only owns the side-effects.
  useEffect(() => {
    if (kernelEvents.length === 0) return;
    const handled = handledBlockedRef.current;
    let lastAlert: InjectionAlert | null = null;

    for (const ke of kernelEvents) {
      // Trigger the cross-panel alert on any kernel deny — pillar-aware
      // (`*_blocked`) types now emit through the bridge, so we accept
      // anything ending in `_blocked` rather than just `connect_blocked`.
      if (!ke.type.endsWith('_blocked')) continue;
      if (handled.has(ke._id)) continue;
      handled.add(ke._id);

      const matchedId = findInjectionTarget(ke, llmEvents);
      lastAlert = {
        kernelId: ke._id,
        toolCallId: matchedId,
        hostname: ke.data?.hostname || ke.data?.dst_ip || 'unknown',
        reason: ke.data?.reason || '',
      };
    }

    if (!lastAlert) return;

    // Banner reveal is staged 300ms after the kernel row appears.
    clearBannerTimers();
    const alert: InjectionAlert = lastAlert;
    const reveal = setTimeout(() => setInjectionAlert(alert), BANNER_REVEAL_DELAY_MS);
    const dismiss = setTimeout(
      () => setInjectionAlert((cur) => (cur && cur.kernelId === alert.kernelId ? null : cur)),
      BANNER_REVEAL_DELAY_MS + BANNER_AUTO_DISMISS_MS,
    );
    bannerTimersRef.current.push(reveal, dismiss);
  }, [kernelEvents, llmEvents]);

  const dismissAlert = () => {
    clearBannerTimers();
    setInjectionAlert(null);
  };

  const agents = useMemo<string[]>(() => {
    const names = new Set<string>();
    for (const e of llmEvents) names.add(e.agent);
    for (const e of kernelEvents) names.add(e.agent);
    return Array.from(names);
  }, [llmEvents, kernelEvents]);

  // Default to the first agent until the user picks one explicitly. Derived
  // rather than synced via setState so we don't run setState in an effect.
  const effectiveActiveAgent = activeAgent ?? agents[0] ?? null;

  const stats = useMemo(() => {
    let toolCalls = 0;
    for (const e of llmEvents) if (e.type === 'tool_call') toolCalls += 1;
    let allowed = 0;
    let blocked = 0;
    for (const e of kernelEvents) {
      // Count any pillar's `_allowed` / `_blocked` plus the legacy
      // `connect_*` types so the stats row works for both the bridge
      // (pillar-aware) and the original mock emitter.
      if (e.type.endsWith('_allowed')) allowed += 1;
      else if (e.type.endsWith('_blocked')) blocked += 1;
    }
    return { toolCalls, allowed, blocked, uptime };
  }, [llmEvents, kernelEvents, uptime]);

  const filteredLlm = effectiveActiveAgent
    ? llmEvents.filter((e) => e.agent === effectiveActiveAgent)
    : llmEvents;
  const filteredKernel = effectiveActiveAgent
    ? kernelEvents.filter((e) => e.agent === effectiveActiveAgent)
    : kernelEvents;

  // The workflow components (UnifiedFlowLayer / AgentFlowLayer /
  // KernelFlowLayer) were written for the legacy `connect_*` schema. To
  // avoid touching those layouts in 14 places, we project pillar-aware
  // kernel events down to legacy types just for the workflow view. The
  // *_blocked → connect_blocked mapping is one-way: the original data is
  // preserved on `data.original_type` so layouts can still surface pillar
  // info if they want to. KernelPanel keeps the rich pillar-aware event
  // unchanged.
  const filteredKernelLegacy = useMemo(() => {
    const map = (e: KernelEvent): KernelEvent => {
      if (e.type === 'connect_attempt' || e.type === 'connect_allowed' || e.type === 'connect_blocked') return e;
      if (e.type.endsWith('_blocked')) return { ...e, type: 'connect_blocked', data: { ...(e.data || {}), original_type: e.type } };
      if (e.type.endsWith('_allowed')) return { ...e, type: 'connect_allowed', data: { ...(e.data || {}), original_type: e.type } };
      return e;
    };
    return filteredKernel.map(map);
  }, [filteredKernel]);

  return (
    <div className="app">
      {/* Top header bar — full width */}
      <Header wsStatus={wsStatus} llmEvents={llmEvents} kernelEvents={kernelEvents} />

      {/* Main body: sidebar + content */}
      <div className="app__body">
        <Sidebar
          agents={agents}
          activeAgent={effectiveActiveAgent}
          onSelectAgent={setActiveAgent}
          llmEvents={llmEvents}
          kernelEvents={kernelEvents}
          stats={stats}
          wsStatus={wsStatus}
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          policyCount={policyCount}
        />

        <div className={`app__main${activeTab === 'workflow' ? ' app__main--workflow' : ''}${activeTab === 'policies' ? ' app__main--policies' : ''}`}>
          {/* Animated ring stats — events tab only */}
          {activeTab === 'events' && <StatRings stats={stats} blockedPulseKey={blockedPulseKey} />}

          {/* ── Events tab ──────────────────────────────────────────── */}
          {activeTab === 'events' && (
            <>
              <LLMAgentLauncher />
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
              <ConnectionTimeline kernelEvents={filteredKernel} />
              <ThreatGauge analysis={latestAnalysis} lastTs={lastAnalysisTs} />
            </>
          )}

          {/* ── Workflow tab ─────────────────────────────────────────── */}
          {activeTab === 'workflow' && (
            <div className="app__workflow">
              <WorkflowGraph llmEvents={filteredLlm} kernelEvents={filteredKernelLegacy} />
            </div>
          )}

          {/* ── Policies tab ─────────────────────────────────────────── */}
          {activeTab === 'policies' && (
            <div className="app__policies">
              <PolicyView onCountChange={setPolicyCount} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
