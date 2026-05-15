// Event union types shared across the viewer app.
//
// All events arrive over a WebSocket connection to the relay (viewer/server)
// and get a synthetic `_id` stamped by App.tsx so React keys and the
// injectionTargets set can use stable integer IDs.

export type LLMEventType =
  | 'stdout'
  | 'tool_call'
  | 'stopped'
  | 'crashed'
  | 'session_start'
  | 'user_input'
  | 'tool_result'
  | 'agent_output';

export type KernelPillar = 'connect' | 'net' | 'file' | 'exec' | 'cred';
export type KernelVerdict = 'attempt' | 'allowed' | 'blocked';
export type KernelEventType = `${KernelPillar}_${KernelVerdict}`;

// Free-form payload — each event type has its own data fields and we don't
// model them exhaustively (the cost of a per-variant union is high and most
// consumers use optional chaining like `e.data?.hostname`).
export type EventData = Record<string, any>;

export interface BaseEvent {
  _id: number;
  agent: string;
  ts: number;
  data?: EventData;
}

export interface LLMEvent extends BaseEvent {
  type: LLMEventType;
}

export interface KernelEvent extends BaseEvent {
  type: KernelEventType;
}

export interface SecurityAnalysisEvent extends BaseEvent {
  type: 'security_analysis';
}

export type AppEvent = LLMEvent | KernelEvent | SecurityAnalysisEvent;

// The security_analysis event's data payload. Comes from viewer/server/analyser.ts.
export interface SecurityAnalysis {
  threatLevel?: 'low' | 'medium' | 'high' | 'critical' | string;
  summary?: string;
  concerns?: string[];
  recommendation?: string;
}

// Stats shape used by Sidebar / StatRings.
export interface Stats {
  toolCalls: number;
  allowed: number;
  blocked: number;
  uptime: number;
}
