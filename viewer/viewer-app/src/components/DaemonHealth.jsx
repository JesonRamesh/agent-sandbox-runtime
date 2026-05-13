import { useEffect, useState } from 'react';
import { pingDaemon } from '../api/daemonApi.js';
import './DaemonHealth.css';

const POLL_INTERVAL_MS = 5000;

export default function DaemonHealth() {
  // 'checking' | 'live' | 'offline'
  const [status, setStatus] = useState('checking');

  useEffect(() => {
    let cancelled = false;

    async function check() {
      const ok = await pingDaemon();
      if (!cancelled) setStatus(ok ? 'live' : 'offline');
    }

    check();
    const id = setInterval(check, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const labels = {
    checking: 'Checking…',
    live:     'Daemon live',
    offline:  'Daemon offline',
  };

  return (
    <div className={`daemon-health daemon-health--${status}`}>
      <span className="daemon-health__dot" />
      <span className="daemon-health__label">{labels[status]}</span>
    </div>
  );
}