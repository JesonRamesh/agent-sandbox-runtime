// mockPolicies.js — seed data used when the daemon is unreachable.
// Mirrors the Policy schema from Mehul's daemon/internal/policy/policy.go.

export const MOCK_POLICIES = [
  {
    id: 1,
    name: 'llm-agent-default',
    mode: 'enforce',
    allowed_hosts: [
      'llm-proxy.dev.outshift.ai:443',
      'api.openai.com:443',
      'example.com:443',
    ],
    allowed_paths: ['/tmp/agent', '/usr/bin', '/usr/lib'],
    allowed_bins:  ['/usr/bin/python3', '/usr/bin/curl'],
    forbidden_caps: ['CAP_SYS_ADMIN', 'CAP_NET_RAW'],
  },
  {
    id: 2,
    name: 'web-fetcher-audit',
    mode: 'audit',
    allowed_hosts: [
      'example.com',
      '93.184.216.34',
      '10.0.0.0/8',
    ],
    allowed_paths: ['/tmp/fetcher', '/var/cache'],
    allowed_bins:  ['/usr/bin/wget'],
    forbidden_caps: [],
  },
  {
    id: 3,
    name: 'shell-runner-strict',
    mode: 'enforce',
    allowed_hosts: [],
    allowed_paths: ['/tmp/runner'],
    allowed_bins:  ['/bin/sh', '/usr/bin/bash'],
    forbidden_caps: ['CAP_SYS_ADMIN', 'CAP_SYS_PTRACE', 'CAP_NET_BIND_SERVICE'],
  },
  {
    id: 4,
    name: 'file-reader-readonly',
    mode: 'audit',
    allowed_hosts: [],
    allowed_paths: ['/var/log', '/etc/config', '/home/agent/docs'],
    allowed_bins:  ['/usr/bin/cat', '/usr/bin/grep', '/usr/bin/awk'],
    forbidden_caps: ['CAP_SYS_ADMIN', 'CAP_DAC_OVERRIDE'],
  },
];
