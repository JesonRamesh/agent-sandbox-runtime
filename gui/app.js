// Vanilla SPA for the agent-sandbox-runtime daemon.
// No build step, no dependencies. Talks to /api/* on the same origin.

const $  = sel => document.querySelector(sel);
const $$ = sel => document.querySelectorAll(sel);

// ----- tabs -----------------------------------------------------------

$$('.tab').forEach(btn => btn.addEventListener('click', () => {
  $$('.tab').forEach(b => b.classList.toggle('active', b === btn));
  const id = btn.dataset.tab;
  $$('.tab-panel').forEach(p =>
    p.classList.toggle('active', p.id === `tab-${id}`));
  if (id === 'policies') refreshPolicies();
}));

// ----- live events ----------------------------------------------------

const tbody = $('#events-table tbody');
const filterInput = $('#event-filter');

function rowMatches(evt) {
  const v = evt.verdict;
  if (v === 'allow' && !$('#show-allow').checked) return false;
  if (v === 'audit' && !$('#show-audit').checked) return false;
  if (v === 'deny'  && !$('#show-deny').checked)  return false;
  const f = filterInput.value.trim().toLowerCase();
  if (!f) return true;
  return JSON.stringify(evt).toLowerCase().includes(f);
}

function detailString(evt) {
  if (evt.net)   return `${evt.net.daddr || '?'}:${evt.net.dport || '?'}`;
  if (evt.file)  return evt.file.path || '(unresolved)';
  if (evt.creds) return `old=${evt.creds.old_id} new=${evt.creds.new_id} caps=0x${(evt.creds.cap_effective>>>0).toString(16)}`;
  if (evt.exec)  return `${evt.exec.filename} (ppid=${evt.exec.ppid})`;
  return '';
}

function appendEvent(evt) {
  if (!rowMatches(evt)) return;
  const tr = document.createElement('tr');
  tr.className = `row-${evt.verdict}`;
  const t = new Date(evt.time).toLocaleTimeString();
  tr.innerHTML = `
    <td>${t}</td>
    <td>${evt.verdict}</td>
    <td>${evt.kind}</td>
    <td>${evt.pid}</td>
    <td>${escapeHTML(evt.comm)}</td>
    <td title="${escapeHTML(JSON.stringify(evt))}">${escapeHTML(detailString(evt))}</td>`;
  tbody.prepend(tr);
  while (tbody.rows.length > 500) tbody.deleteRow(-1);
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

$('#clear-events').addEventListener('click', () => tbody.innerHTML = '');

// ----- SSE connection -------------------------------------------------

function connect() {
  const status = $('#status');
  const es = new EventSource('/api/events');
  es.onopen    = () => { status.textContent = 'live';      status.className = 'pill pill-ok'; };
  es.onerror   = () => { status.textContent = 'reconnect'; status.className = 'pill pill-down';
                         es.close(); setTimeout(connect, 2000); };
  es.onmessage = e => {
    try { appendEvent(JSON.parse(e.data)); }
    catch (err) { console.error('bad event', err, e.data); }
  };
}
connect();

// Backfill the recent buffer on first load.
fetch('/api/events/recent').then(r => r.json()).then(arr => {
  arr.reverse().forEach(appendEvent);
}).catch(() => {});

// ----- policies -------------------------------------------------------

const editor = $('#policy-editor');
const list   = $('#policy-list');

function refreshPolicies() {
  fetch('/api/policies').then(r => r.json()).then(arr => {
    list.innerHTML = '';
    arr.sort((a, b) => a.id - b.id).forEach(p => list.appendChild(card(p)));
  });
}

function card(p) {
  const el = document.createElement('div');
  el.className = 'policy-card';
  el.innerHTML = `
    <h3>#${p.id} — ${escapeHTML(p.name || '(unnamed)')}</h3>
    <div class="mode-${p.mode}">${p.mode || 'audit'}</div>
    <ul>
      <li>${(p.allowed_hosts  || []).length} host rules</li>
      <li>${(p.allowed_paths  || []).length} path rules</li>
      <li>${(p.allowed_bins   || []).length} binary rules</li>
      <li>${(p.forbidden_caps || []).length} forbidden caps</li>
    </ul>
    <button class="edit">Edit</button>`;
  el.querySelector('.edit').addEventListener('click', () => openEditor(p));
  return el;
}

$('#new-policy').addEventListener('click', () => openEditor({
  id: '', name: '', mode: 'audit',
  allowed_hosts: [], allowed_paths: [], allowed_bins: [], forbidden_caps: [],
}));

function openEditor(p) {
  const f = editor.querySelector('form');
  f.id.value             = p.id || '';
  f.name.value           = p.name || '';
  f.mode.value           = p.mode || 'audit';
  f.allowed_hosts.value  = (p.allowed_hosts  || []).join('\n');
  f.allowed_paths.value  = (p.allowed_paths  || []).join('\n');
  f.allowed_bins.value   = (p.allowed_bins   || []).join('\n');
  f.forbidden_caps.value = (p.forbidden_caps || []).join('\n');
  $('#editor-title').textContent = p.id ? `Edit policy #${p.id}` : 'New policy';
  editor.showModal();
}

editor.addEventListener('close', () => {
  if (editor.returnValue !== 'save') return;
  const f = editor.querySelector('form');
  const lines = name => f[name].value.split('\n').map(s => s.trim()).filter(Boolean);
  const body = {
    id:             Number(f.id.value),
    name:           f.name.value,
    mode:           f.mode.value,
    allowed_hosts:  lines('allowed_hosts'),
    allowed_paths:  lines('allowed_paths'),
    allowed_bins:   lines('allowed_bins'),
    forbidden_caps: lines('forbidden_caps'),
  };
  fetch(`/api/policies/${body.id}`, {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  }).then(refreshPolicies);
});

// ----- bindings -------------------------------------------------------

$('#bind-form').addEventListener('submit', e => {
  e.preventDefault();
  const f = e.target;
  fetch('/api/bindings', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      cgroup_id: Number(f.cgroup_id.value),
      policy_id: Number(f.policy_id.value),
    }),
  }).then(() => { f.reset(); });
});
