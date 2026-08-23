/* Incident Report Generator — front-end behavior
 * No inline scripts (CSP script-src 'self'); everything lives here.
 */

const SEV_CLASS = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Informational: 'informational' };
const TLP_CLASS = { 'TLP:RED': 'tlp-red', 'TLP:AMBER': 'tlp-amber', 'TLP:GREEN': 'tlp-green', 'TLP:CLEAR': 'tlp-clear' };
const HISTORY_KEY = 'irg_report_history_v1';
const MAX_HISTORY = 8;

// ---------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------
function toast(message, type = 'success') {
  const stack = document.getElementById('toast-stack');
  const el = document.createElement('div');
  el.className = `toast${type === 'error' ? ' error' : ''}`;
  el.textContent = message;
  stack.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

// ---------------------------------------------------------------------
// Live status bar: clock + severity/TLP badges reflect form state
// ---------------------------------------------------------------------
function tickClock() {
  const el = document.getElementById('clock');
  const now = new Date();
  el.textContent = now.toISOString().slice(0, 19).replace('T', ' ') + 'Z';
}
setInterval(tickClock, 1000);
tickClock();

function updateStatusBadges() {
  const sev = document.getElementById('f-severity').value;
  const tlp = document.getElementById('f-classification').value;

  const sevEl = document.getElementById('sb-severity');
  sevEl.className = `badge badge-${SEV_CLASS[sev] || 'medium'}`;
  sevEl.innerHTML = `<span class="swatch"></span>${sev}`;

  const tlpEl = document.getElementById('sb-tlp');
  tlpEl.className = `badge badge-${TLP_CLASS[tlp] || 'tlp-amber'}`;
  tlpEl.innerHTML = `<span class="swatch"></span>${tlp}`;
}
document.getElementById('f-severity').addEventListener('change', updateStatusBadges);
document.getElementById('f-classification').addEventListener('change', updateStatusBadges);
updateStatusBadges();

// ---------------------------------------------------------------------
// Character counters
// ---------------------------------------------------------------------
function wireCounter(fieldId, counterId, max) {
  const field = document.getElementById(fieldId);
  const counter = document.getElementById(counterId);
  if (!field || !counter) return;
  const update = () => { counter.textContent = `${field.value.length}/${max}`; };
  field.addEventListener('input', update);
  update();
}
wireCounter('f-title', 'c-title', 200);
wireCounter('f-affected_systems', 'c-sys', 2000);
wireCounter('f-description', 'c-desc', 5000);

// ---------------------------------------------------------------------
// Generate Incident ID
// ---------------------------------------------------------------------
document.getElementById('gen-id-btn').addEventListener('click', () => {
  const year = new Date().getUTCFullYear();
  const rand = Math.floor(1000 + Math.random() * 9000);
  document.getElementById('f-incident_id').value = `INC-${year}-${rand}`;
});

// ---------------------------------------------------------------------
// Sample data
// ---------------------------------------------------------------------
const SAMPLE = {
  incident_id: 'INC-2026-0142',
  title: 'Phishing-driven credential compromise on corporate VPN',
  severity: 'High',
  status: 'Contained',
  classification: 'TLP:AMBER',
  date_reported: '2026-08-18',
  date_occurred: '2026-08-17',
  reported_by: 'SOC Tier 1 Analyst',
  report_author: 'IR Lead',
  affected_systems: 'mail-gw-02, corp-vpn-01, FIN-WS-014',
  description: 'A finance employee clicked a spear-phishing link and submitted VPN credentials to a spoofed portal. Credentials were used ~40 minutes later from an unrecognized ASN.',
  timeline_raw: '2026-08-17 08:52 | Phishing email delivered, bypassed spam filter\n2026-08-17 08:59 | User submitted credentials to spoofed portal\n2026-08-17 09:38 | Anomalous VPN login detected by SIEM\n2026-08-17 09:55 | Account disabled, session terminated',
  iocs_raw: '185.220.101.44\nvpn-corp-secure-login.example-phish.com',
  impact_assessment: 'One account compromised. No lateral movement or data exfiltration observed.',
  containment_actions: 'Disabled account, terminated session, reset credentials, blocked malicious domain/IP at the perimeter.',
  eradication_actions: 'Full AV/EDR scan on affected endpoints — no malware found.',
  recovery_actions: 'Re-enabled account with new credentials, enforced MFA re-registration.',
  root_cause: 'Lookalike domain evaded email security controls; no phishing-resistant MFA in place.',
  recommendations: 'Roll out FIDO2/WebAuthn MFA for VPN access. Add lookalike-domain detection to the email gateway.',
};

document.getElementById('sample-btn').addEventListener('click', () => {
  const form = document.getElementById('report-form');
  for (const [key, value] of Object.entries(SAMPLE)) {
    const field = form.elements[key];
    if (field) field.value = value;
  }
  updateStatusBadges();
  document.getElementById('f-title').dispatchEvent(new Event('input'));
  document.getElementById('f-affected_systems').dispatchEvent(new Event('input'));
  document.getElementById('f-description').dispatchEvent(new Event('input'));
  toast('Sample incident loaded');
});

document.getElementById('clear-btn').addEventListener('click', () => {
  document.getElementById('report-form').reset();
  updateStatusBadges();
  ['f-title', 'f-affected_systems', 'f-description'].forEach(id =>
    document.getElementById(id).dispatchEvent(new Event('input')));
  toast('Form cleared');
});

// ---------------------------------------------------------------------
// Payload collection
// ---------------------------------------------------------------------
function collectPayload() {
  const f = document.getElementById('report-form');
  const fd = new FormData(f);
  const data = Object.fromEntries(fd.entries());

  data.timeline = (data.timeline_raw || '').split('\n').filter(l => l.trim()).map(line => {
    const [ts, ...rest] = line.split('|');
    return { timestamp: (ts || '').trim(), description: rest.join('|').trim() };
  });
  delete data.timeline_raw;

  data.indicators_of_compromise = (data.iocs_raw || '').split('\n').map(s => s.trim()).filter(Boolean);
  delete data.iocs_raw;

  return data;
}

function setBusy(busy) {
  document.getElementById('gen-btn').disabled = busy;
  document.getElementById('pdf-btn').disabled = busy;
  if (busy) document.getElementById('gen-btn').textContent = 'Generating…';
  else document.getElementById('gen-btn').textContent = 'Generate report';
}

// ---------------------------------------------------------------------
// History (client-side only, this browser)
// ---------------------------------------------------------------------
function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  } catch {
    return [];
  }
}

function saveToHistory(entry) {
  const history = loadHistory();
  history.unshift(entry);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)));
  renderHistory();
}

function renderHistory() {
  const history = loadHistory();
  const panel = document.getElementById('history-panel');
  const list = document.getElementById('history-list');
  if (!history.length) { panel.hidden = true; return; }
  panel.hidden = false;
  list.innerHTML = '';
  history.forEach(item => {
    const div = document.createElement('div');
    div.className = 'history-item';
    div.innerHTML = `
      <div>
        <div class="h-title">${item.title}</div>
        <div class="h-meta">${item.incident_id} · ${item.severity} · ${item.generated_at}</div>
      </div>
      <span class="badge badge-${SEV_CLASS[item.severity] || 'medium'}"><span class="swatch"></span>${item.severity}</span>
    `;
    div.addEventListener('click', () => {
      renderReport(item.markdown, item.integrity_hash);
      toast(`Loaded ${item.incident_id} from history`);
    });
    list.appendChild(div);
  });
}

// ---------------------------------------------------------------------
// Rendering the report into the console panel
// ---------------------------------------------------------------------
function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

let lastMarkdown = '';

function renderReport(markdown, hash) {
  lastMarkdown = markdown;
  document.getElementById('console-body').innerHTML = `<pre class="report-md">${esc(markdown)}</pre>`;
  const hashRow = document.getElementById('hash-row');
  hashRow.hidden = false;
  document.getElementById('hash-value').textContent = hash;
  document.getElementById('console-actions').hidden = false;
}

function renderErrors(errors) {
  document.getElementById('console-body').innerHTML =
    `<div class="error-box"><strong>Validation failed</strong><ul>${errors.map(e => `<li>${esc(e)}</li>`).join('')}</ul></div>`;
  document.getElementById('hash-row').hidden = true;
  document.getElementById('console-actions').hidden = true;
}

// ---------------------------------------------------------------------
// Submit handlers
// ---------------------------------------------------------------------
document.getElementById('report-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setBusy(true);
  try {
    const res = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(collectPayload()),
    });
    const data = await res.json();
    if (!res.ok) {
      renderErrors(data.details || [data.error || 'Unknown error']);
      toast('Validation failed — check the report panel', 'error');
      return;
    }
    renderReport(data.markdown, data.integrity_hash);
    saveToHistory({
      incident_id: data.incident_id,
      title: document.getElementById('f-title').value,
      severity: document.getElementById('f-severity').value,
      generated_at: data.generated_at,
      integrity_hash: data.integrity_hash,
      markdown: data.markdown,
    });
    toast('Report generated');
  } catch (err) {
    toast('Request failed — check your connection', 'error');
  } finally {
    setBusy(false);
  }
});

document.getElementById('copy-md-btn').addEventListener('click', async () => {
  await navigator.clipboard.writeText(lastMarkdown);
  toast('Markdown copied to clipboard');
});

document.getElementById('copy-hash-btn').addEventListener('click', async () => {
  const hash = document.getElementById('hash-value').textContent;
  await navigator.clipboard.writeText(hash);
  toast('Hash copied to clipboard');
});

// ---------------------------------------------------------------------
// Download menu (PDF / Markdown / Print)
// ---------------------------------------------------------------------
const dlTrigger = document.getElementById('dl-trigger');
const dlMenu = document.getElementById('dl-menu');

function openDlMenu() {
  dlMenu.hidden = false;
  dlTrigger.setAttribute('aria-expanded', 'true');
}
function closeDlMenu() {
  dlMenu.hidden = true;
  dlTrigger.setAttribute('aria-expanded', 'false');
}

dlTrigger.addEventListener('click', (e) => {
  e.stopPropagation();
  if (dlMenu.hidden) openDlMenu(); else closeDlMenu();
});

document.addEventListener('click', (e) => {
  if (!dlMenu.hidden && !dlMenu.contains(e.target) && e.target !== dlTrigger) closeDlMenu();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !dlMenu.hidden) { closeDlMenu(); dlTrigger.focus(); }
});

async function downloadPdf() {
  setBusy(true);
  try {
    const res = await fetch('/api/generate_pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(collectPayload()),
    });
    if (!res.ok) {
      const data = await res.json();
      renderErrors(data.details || [data.error || 'Unknown error']);
      toast('Validation failed — check the report panel', 'error');
      return;
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    const id = document.getElementById('f-incident_id').value || 'report';
    a.href = url;
    a.download = `incident_report_${id}.pdf`;
    a.click();
    window.URL.revokeObjectURL(url);
    toast('PDF downloaded');
  } catch (err) {
    toast('Request failed — check your connection', 'error');
  } finally {
    setBusy(false);
  }
}

function downloadMarkdown() {
  if (!lastMarkdown) { toast('Generate a report first', 'error'); return; }
  const id = document.getElementById('f-incident_id').value || 'report';
  const blob = new Blob([lastMarkdown], { type: 'text/markdown;charset=utf-8' });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `incident_report_${id}.md`;
  a.click();
  window.URL.revokeObjectURL(url);
  toast('Markdown file downloaded');
}

document.getElementById('dl-pdf').addEventListener('click', () => { closeDlMenu(); downloadPdf(); });
document.getElementById('dl-md').addEventListener('click', () => { closeDlMenu(); downloadMarkdown(); });
document.getElementById('dl-print').addEventListener('click', () => { closeDlMenu(); window.print(); });

// Top-level quick "Download PDF" button (in the form) still works the same way
document.getElementById('pdf-btn').addEventListener('click', downloadPdf);

// Init
renderHistory();
