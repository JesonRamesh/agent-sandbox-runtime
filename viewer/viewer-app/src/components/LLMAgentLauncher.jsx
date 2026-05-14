import { useState } from 'react';
import { runLlmAgent } from '../api/daemonApi.js';
import './LLMAgentLauncher.css';

// Compact launcher for the orchestrator's run_llm_agent.py. Sends a
// free-form task to /api/llm/run; the relay spawns the python script
// and the resulting session_start / tool_call / agent_output events
// arrive over the WebSocket and populate the workflow tab live.
//
// `state` is one of: 'idle' | 'running' | { ok, message }.
export default function LLMAgentLauncher() {
  const [task, setTask] = useState('Fetch the front page of https://example.com and summarise.');
  const [state, setState] = useState('idle');

  async function handleRun(e) {
    e.preventDefault();
    if (!task.trim() || state === 'running') return;
    setState('running');
    try {
      const r = await runLlmAgent(task.trim());
      setState({ ok: true, message: `pid ${r.pid} started — switch to the Workflow tab to watch` });
    } catch (err) {
      setState({ ok: false, message: err.message });
    }
    // Clear status after a few seconds; events themselves are the real feedback.
    setTimeout(() => setState((s) => (s && s !== 'running' ? 'idle' : s)), 8000);
  }

  const running = state === 'running';
  const result  = state && state !== 'running' && state !== 'idle' ? state : null;

  return (
    <form className="llm-launcher" onSubmit={handleRun}>
      <span className="llm-launcher__label">LLM agent</span>
      <input
        className="llm-launcher__input"
        type="text"
        value={task}
        onChange={(e) => setTask(e.target.value)}
        placeholder="Type a task for the LLM-driven agent (e.g. 'fetch https://example.com')"
        disabled={running}
        spellCheck={false}
      />
      <button
        type="submit"
        className={
          'llm-launcher__btn' +
          (running ? ' is-running' : '') +
          (result?.ok === true ? ' is-ok' : '') +
          (result?.ok === false ? ' is-fail' : '')
        }
        disabled={running || !task.trim()}
        title={result?.message || 'Send the task to the orchestrator (run_llm_agent.py)'}
      >
        {running ? '…' : result?.ok === true ? '✓ Sent' : result?.ok === false ? '✗ Failed' : '▶ Run'}
      </button>
      {result && (
        <span className={`llm-launcher__status ${result.ok ? 'is-ok' : 'is-fail'}`}>
          {result.message}
        </span>
      )}
    </form>
  );
}
