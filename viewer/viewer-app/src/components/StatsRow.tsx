import './StatsRow.css';

interface Stats {
  toolCalls?: number;
  allowed?: number;
  blocked?: number;
  uptime?: number;
}

interface Props {
  stats?: Stats | null;
  blockedPulseKey?: number;
}

function formatUptime(seconds: number | undefined): string {
  const s = Math.max(0, Math.floor(seconds || 0));
  const m = Math.floor(s / 60);
  const r = s % 60;
  if (m === 0) return `${r}s`;
  return `${m}m ${r.toString().padStart(2, '0')}s`;
}

export default function StatsRow({ stats, blockedPulseKey = 0 }: Props) {
  const { toolCalls = 0, allowed = 0, blocked = 0, uptime = 0 } = stats || {};
  const cards = [
    { id: 'tool',    label: 'tool calls',          value: toolCalls,             tone: 'neutral' },
    { id: 'allowed', label: 'connections allowed', value: allowed,               tone: 'good'    },
    { id: 'blocked', label: 'connections blocked', value: blocked,               tone: 'bad'     },
    { id: 'uptime',  label: 'uptime',              value: formatUptime(uptime),  tone: 'neutral' },
  ];
  return (
    <div className="stats-row">
      {cards.map((c) => {
        const isPulsing = c.id === 'blocked' && blockedPulseKey > 0;
        // Remount the bad card when the pulse key changes so the CSS animation
        // restarts from frame 0 each time the blocked count ticks up.
        const key = c.id === 'blocked' ? `blocked-${blockedPulseKey}` : c.id;
        return (
          <div
            key={key}
            className={`stats-row__card tone-${c.tone}${isPulsing ? ' is-pulsing' : ''}`}
          >
            <div className="stats-row__value">{c.value}</div>
            <div className="stats-row__label">{c.label}</div>
          </div>
        );
      })}
    </div>
  );
}
