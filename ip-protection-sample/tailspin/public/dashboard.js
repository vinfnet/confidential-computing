'use strict';
import { OperatorSession } from './session.js';

const byId = (id) => document.getElementById(id);
let config;
let refreshing = false;
let busy = false;
const session = new OperatorSession({
  onChange: signedIn,
  onExpired: () => {
    byId('login-status').textContent = 'Your operator session expired. Sign in again.';
    message('Your operator session expired. Sign in again.', true);
  }
});

function message(text, error = false) {
  byId('status').textContent = text;
  byId('status').classList.toggle('error', error);
}
function controls(enabled) {
  document.querySelectorAll('[data-action]').forEach((button) => {
    button.disabled = !session.user || !enabled || busy;
  });
}
function signedIn(user) {
  byId('account-label').textContent = user || 'Operator signed out';
  byId('logout').textContent = 'Sign out';
  byId('login-panel').hidden = !!user;
  byId('logout').hidden = !user;
  if (!user) {
    refreshing = false;
    busy = false;
    controls(false);
    for (const [id, text] of Object.entries({
      'trust-value': 'Locked', 'trust-detail': 'Operator authentication required',
      'heartbeat-value': 'Unknown', 'heartbeat-detail': 'Sign in to view verified receipts',
      'availability-value': '—', 'availability-detail': 'Sign in to view verified samples',
      'latency-value': '—', 'latency-detail': 'Sign in to view verified metrics',
      cycles: '—', defects: '—', uptime: '—', 'operator-status': 'Sign-in required',
      'release-status': 'Unknown', 'key-status': 'Unknown', 'evidence-status': 'No records loaded',
      'sample-count': '0 SAMPLES', 'chart-range': 'No measurements', 'last-refresh': 'Not connected',
      'action-result': 'Actions require an authorized operator and a healthy Tailspin release gate.'
    })) byId(id).textContent = text;
    byId('chart').replaceChildren();
    table('telemetry-body', [], Array(6), 'Sign in to view telemetry.');
    table('security-body', [], Array(4), 'Sign in to view security activity.');
  }
}
const number = (value, digits = 0) => new Intl.NumberFormat(undefined, { maximumFractionDigits: digits }).format(value);
const duration = (seconds) => seconds >= 86400 ? `${number(seconds / 86400, 1)}d` :
  seconds >= 3600 ? `${number(seconds / 3600, 1)}h` : seconds >= 60 ? `${number(seconds / 60, 1)}m` : `${number(seconds)}s`;
const time = (value) => value ? new Date(value).toLocaleTimeString() : '—';

function table(id, rows, columns, empty) {
  const target = byId(id);
  target.replaceChildren();
  if (!rows.length) {
    const row = target.insertRow();
    const cell = row.insertCell();
    cell.colSpan = columns.length;
    cell.className = 'empty';
    cell.textContent = empty;
    return;
  }
  rows.forEach((value) => {
    const row = target.insertRow();
    columns.forEach((column) => {
      const cell = row.insertCell();
      cell.textContent = column(value);
    });
  });
}
function render(data) {
  byId('trust-value').textContent = data.selfReleaseReady ? 'Verified' : 'Unavailable';
  byId('trust-detail').textContent = data.selfReleaseReady ? 'Self-key release succeeded recently' : 'Sensitive operations are blocked';
  byId('heartbeat-value').textContent = data.heartbeat.status === 'receiving' ? 'Receiving' :
    data.heartbeat.status === 'stale' ? 'Stale' : 'Unknown';
  byId('heartbeat-detail').textContent = data.heartbeat.lastSeen ?
    `Last verified receipt ${duration(Math.floor(data.heartbeat.ageMs / 1000))} ago` : 'No verified worker sample yet';
  byId('availability-value').textContent = data.availability.protectedSamplePercent === null ? '—' :
    `${number(data.availability.protectedSamplePercent, 1)}%`;
  byId('availability-detail').textContent = data.availability.sampleCount ?
    `${number(data.availability.sampleCount)} verified samples in last hour` : 'Unknown until samples arrive';
  const latest = data.records[0];
  byId('latency-value').textContent = latest ? `${number(latest.latencyMs)} ms` : '—';
  byId('latency-detail').textContent = latest ? `Reported ${time(latest.at)} · ${latest.state}` : 'Waiting for verified metrics';
  byId('cycles').textContent = latest ? number(latest.completedCycles) : '—';
  byId('defects').textContent = latest ? `${number(latest.defectRate * 100, 2)}%` : '—';
  byId('uptime').textContent = latest ? duration(latest.uptimeSeconds) : '—';
  byId('operator-status').textContent = 'Authenticated session';
  byId('release-status').textContent = data.selfReleaseReady ? 'Verified' : 'Unavailable';
  byId('key-status').textContent = data.workerKey.status;
  byId('evidence-status').textContent = data.heartbeat.status === 'receiving' ? 'Fresh verified heartbeat' :
    data.heartbeat.status === 'stale' ? 'Stale heartbeat' : 'No verified sample';
  byId('sample-count').textContent = `${data.records.length} SAMPLES`;
  table('telemetry-body', data.records, [
    (r) => time(r.at), (r) => r.state, (r) => `${number(r.latencyMs, 1)} ms`,
    (r) => number(r.completedCycles), (r) => `${number(r.defectRate * 100, 2)}%`,
    (r) => duration(r.uptimeSeconds)
  ], 'Waiting for the first attested worker sample.');
  table('security-body', data.securityEvents, [
    (r) => time(r.at), (r) => r.event.replaceAll('_', ' '), (r) => r.outcome,
    (r) => r.reason ? r.reason.replaceAll('_', ' ') : '—'
  ], 'No security events received.');
  const samples = data.records.slice(0, 32).reverse();
  const chart = byId('chart');
  if (samples.length) {
    chart.replaceChildren();
    const maximum = Math.max(1, ...samples.map((r) => r.latencyMs));
    // SVG attributes avoid dynamic inline styles, keeping the page's CSP strict.
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 640 165');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '165');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Worker-measured cycle latency; recent signature-verified reports');
    samples.forEach((sample, index) => {
      const rect = document.createElementNS(svg.namespaceURI, 'rect');
      const height = Math.max(2, sample.latencyMs / maximum * 150);
      const step = 640 / samples.length;
      for (const [name, value] of Object.entries({
        x: index * step + 2, y: 165 - height, width: Math.max(1, step - 5), height, rx: 3, fill: '#3ac2a4'
      })) rect.setAttribute(name, String(value));
      const title = document.createElementNS(svg.namespaceURI, 'title');
      title.textContent = `${time(sample.at)}: ${number(sample.latencyMs, 1)} ms (worker measured; signed report)`;
      rect.append(title);
      svg.append(rect);
    });
    chart.append(svg);
    byId('chart-range').textContent = `Peak ${number(maximum, 1)} ms`;
  }
  byId('last-refresh').textContent = `Updated ${new Date().toLocaleTimeString()}`;
  controls(data.selfReleaseReady);
}
async function refresh() {
  if (refreshing || !session.user) return;
  const generation = session.generation;
  refreshing = true;
  try {
    const data = await session.request('/api/dashboard');
    if (generation !== session.generation || !session.user) return;
    render(data);
    message(data.selfReleaseReady ?
      'Connected · operator authorized · signed worker measurements; defect rate is synthetic. Measurements are not independently proven.' :
      'Tailspin key release unavailable · showing historical receipts only; sensitive operations are blocked.',
    !data.selfReleaseReady);
  } catch (error) {
    if (generation !== session.generation || !session.user) return;
    controls(false);
    byId('trust-value').textContent = 'Unavailable';
    byId('trust-detail').textContent = 'Fresh dashboard validation failed';
    byId('operator-status').textContent = 'Not freshly verified';
    byId('last-refresh').textContent = 'Connection interrupted · displayed data may be stale';
    message(error.message, true);
  } finally { if (generation === session.generation) refreshing = false; }
}
async function publicReadiness() {
  if (session.user) return refresh();
  const generation = session.generation;
  try {
    const response = await fetch('/api/health', { cache: 'no-store', signal: AbortSignal.timeout(6000) });
    const health = await response.json();
    if (session.user || generation !== session.generation) return;
    byId('trust-value').textContent = health.ready ? 'Ready' : 'Unavailable';
    byId('trust-detail').textContent = health.ready ? 'Sign in for verified operations' : 'Self-key release not ready; operations blocked';
    byId('release-status').textContent = health.ready ? 'Ready' : 'Unavailable';
    message(health.ready ? 'Sign in with your operator credentials to view authorized operations.' :
      'Tailspin key release is unavailable. The dashboard remains accessible; sensitive operations are blocked.', !health.ready);
  } catch {
    if (!session.user && generation === session.generation) {
      message('Readiness unavailable. Check HTTPS connectivity and demo CA trust.', true);
    }
  }
}
async function initialize() {
  config = await (await fetch('/api/config', { cache: 'no-store' })).json();
  byId('worker-link').href = `${config.workerUrl}/`;
  byId('worker-link').hidden = false;
  byId('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    byId('login').disabled = true;
    try {
      await session.login(byId('username').value, byId('password').value);
      byId('login-status').textContent = 'Signed in with a secure operator session.';
      await refresh();
    } catch (error) {
      byId('login-status').textContent = `Sign-in failed: ${error.message}`;
      message(`Sign-in failed: ${error.message}`, true);
    } finally {
      byId('password').value = '';
      byId('login').disabled = false;
    }
  });
  byId('logout').addEventListener('click', async () => {
    byId('logout').disabled = true;
    byId('password').value = '';
    try {
      await session.logout();
      byId('login-status').textContent = 'Signed out. Protected dashboard data was cleared.';
      message('Signed out. Protected dashboard data was cleared.');
    } catch {
      byId('logout').hidden = false;
      byId('logout').textContent = 'Retry sign out';
      message('Local view cleared; server sign-out could not be confirmed. Retry sign out.', true);
    } finally { byId('logout').disabled = false; }
  });
  document.querySelectorAll('[data-action]').forEach((button) => button.addEventListener('click', async () => {
    const action = button.dataset.action;
    if (busy || !session.user) return;
    if (action === 'revoke' && !confirm('Disable ALL enabled versions of the Contoso robot key? This affects real Azure resources. Keys already in worker memory cannot be recalled. Restart the worker afterward.')) return;
    busy = true;
    const generation = session.generation;
    controls(false);
    byId('action-result').textContent = `${action}: submitting real Azure operation…`;
    try {
      const result = await session.request(`/api/actions/${action}`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
      });
      if (generation !== session.generation || !session.user) return;
      byId('action-result').textContent = `${action}: ${result.status}. ` +
        (action === 'revoke' ? `${result.disabledVersions} key version(s) disabled. ${result.detail}` :
          `ARM HTTP ${result.upstreamStatus}; request accepted, not confirmation of successful provisioning. Check Azure for completion.`);
    } catch (error) {
      if (generation === session.generation && session.user) {
        byId('action-result').textContent = `${action}: ${error.message}`;
      }
    } finally {
      if (generation === session.generation) { busy = false; await refresh(); }
    }
  }));
  await session.restore();
  await publicReadiness();
  setInterval(() => publicReadiness(), 5000);
}
initialize().catch(() => {
  controls(false);
  message('Could not initialize the secure control room. Check HTTPS connectivity and operator session configuration.', true);
});
