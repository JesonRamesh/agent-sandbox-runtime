'use strict';

const ANALYSIS_INTERVAL_MS = 30_000;

const PROMPT_PREFIX = `You are a security analyst reviewing AI agent activity logs.
Analyse the following events and respond with ONLY valid JSON — no markdown, no explanation.
JSON shape:
{
  "threatLevel": "low" | "medium" | "high" | "critical",
  "summary": "<one sentence>",
  "concerns": ["<concern 1>", ...],
  "recommendation": "<one sentence>"
}

Events:
`;

function buildPrompt(events) {
  const lines = events.map((e) => JSON.stringify(e)).join('\n');
  return PROMPT_PREFIX + lines;
}

function startAnalyser(getRecentEvents, broadcastFn) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    console.warn('[analyser] OPENAI_API_KEY not set — security analysis disabled');
    return;
  }

  // Lazy-require so the server still starts if openai isn't installed yet.
  let OpenAI;
  try {
    OpenAI = require('openai');
  } catch {
    console.warn('[analyser] openai package not found — security analysis disabled');
    return;
  }

  const client = new OpenAI({
    apiKey,
    baseURL: 'https://llm-proxy.dev.outshift.ai/v1',
  });

  const model = process.env.LLM_MODEL || 'gpt-4o';

  async function analyse() {
    const events = getRecentEvents();
    if (events.length === 0) return;

    let analysis;
    try {
      const completion = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: buildPrompt(events) }],
        max_tokens: 500,
      });
      analysis = JSON.parse(completion.choices[0].message.content);
    } catch (err) {
      console.warn('[analyser] analysis failed:', err.message);
      return;
    }

    const event = {
      agent: 'system',
      type: 'security_analysis',
      ts: Date.now() / 1000,
      data: {
        threatLevel: analysis.threatLevel || 'low',
        summary: analysis.summary || '',
        concerns: Array.isArray(analysis.concerns) ? analysis.concerns : [],
        recommendation: analysis.recommendation || '',
      },
    };

    broadcastFn(JSON.stringify(event));
    console.log(`[analyser] broadcast security_analysis (threatLevel=${event.data.threatLevel})`);
  }

  setInterval(analyse, ANALYSIS_INTERVAL_MS);
  console.log(`[analyser] started — analysing every ${ANALYSIS_INTERVAL_MS / 1000}s using ${model}`);
}

module.exports = { startAnalyser };
