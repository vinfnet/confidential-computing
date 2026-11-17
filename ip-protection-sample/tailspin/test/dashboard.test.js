import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { OperatorSession } from '../public/session.js';

class Element {
  constructor() {
    this.children = [];
    this.listeners = {};
    this.classList = { toggle() {} };
    this.value = '';
  }
  set textContent(value) { this.text = value; this.children = []; }
  get textContent() { return this.text || this.children.map((child) => child.textContent).join(''); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  append(child) { this.children.push(child); }
  insertRow() { const row = new Element(); this.append(row); return row; }
  insertCell() { const cell = new Element(); this.append(cell); return cell; }
  setAttribute(name, value) { this[name] = value; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
}

const response = (body, status = 200) => ({ status, ok: status < 400, json: async () => body });
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
const tick = () => new Promise(setImmediate);
const dashboard = {
  selfReleaseReady: true, workerKey: { status: 'enabled' },
  heartbeat: { status: 'receiving', lastSeen: '2026-01-01T00:00:00Z', ageMs: 100 },
  availability: { protectedSamplePercent: 100, sampleCount: 1 },
  records: [{ at: '2026-01-01T00:00:00Z', state: 'protected', latencyMs: 123,
    completedCycles: 77, uptimeSeconds: 100, defectRate: 0.01 }],
  securityEvents: [{ at: '2026-01-01T00:00:00Z', event: 'worker_attestation_and_proof', outcome: 'verified' }]
};

async function browser() {
  const elements = new Map();
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const buttons = ['deploy', 'restart', 'revoke'].map((action) => {
    const element = new Element();
    element.dataset = { action };
    return element;
  });
  const overrides = new Map();
  let poll;
  let authenticated = true;
  const fetchImpl = async (url, options) => {
    if (overrides.has(url)) return overrides.get(url)(options);
    if (url === '/api/config') return response({ workerUrl: 'https://worker.example' });
    if (url === '/api/session') return response({ authenticated, ...(authenticated ? { user: 'operator' } : {}) });
    if (url === '/api/dashboard') return response(dashboard);
    if (url === '/api/health') return response({ ready: true });
    if (url === '/api/login') { authenticated = true; return response({ authenticated: true }); }
    if (url === '/api/logout') { authenticated = false; return response({ authenticated: false }); }
    throw new Error(`Unexpected request: ${url}`);
  };
  const source = (await readFile(new URL('../public/dashboard.js', import.meta.url), 'utf8'))
    .replace("import { OperatorSession } from './session.js';", '');
  vm.runInNewContext(source, {
    OperatorSession: class extends OperatorSession {
      constructor(options) { super({ ...options, fetchImpl }); }
    },
    document: {
      getElementById: byId, querySelectorAll: () => buttons,
      createElementNS: () => new Element()
    },
    fetch: fetchImpl, AbortSignal, Intl, Date, confirm: () => true,
    setInterval: (callback) => { poll = callback; }
  });
  await tick();
  assert.equal(byId('cycles').textContent, '77');
  return { byId, buttons, overrides, poll: () => poll() };
}

function assertCleared({ byId, buttons }) {
  assert.equal(byId('cycles').textContent, '—');
  assert.equal(byId('uptime').textContent, '—');
  assert.equal(byId('sample-count').textContent, '0 SAMPLES');
  assert.equal(byId('chart').children.length, 0);
  assert.equal(byId('telemetry-body').textContent, 'Sign in to view telemetry.');
  assert.equal(byId('security-body').textContent, 'Sign in to view security activity.');
  assert.ok(buttons.every((button) => button.disabled));
  assert.equal(byId('login-panel').hidden, false);
}

test('dashboard clears real rendered records/controls immediately and ignores late poll/action after logout', async () => {
  const page = await browser();
  const pendingDashboard = deferred();
  const pendingAction = deferred();
  page.overrides.set('/api/dashboard', () => pendingDashboard.promise);
  page.overrides.set('/api/actions/restart', () => pendingAction.promise);
  const polling = page.poll();
  const action = page.buttons[1].listeners.click();
  const logout = page.byId('logout').listeners.click();
  assertCleared(page);
  await logout;
  const signedOutActionText = page.byId('action-result').textContent;
  pendingDashboard.resolve(response(dashboard));
  pendingAction.resolve(response({ status: 'accepted', upstreamStatus: 202 }));
  await Promise.all([polling, action]);
  assertCleared(page);
  assert.equal(page.byId('action-result').textContent, signedOutActionText);
});

test('expired dashboard session clears protected UI and displays explicit reauthentication error', async () => {
  const page = await browser();
  page.overrides.set('/api/dashboard', () => response({ error: 'operator_sign_in_required' }, 401));
  await page.poll();
  assertCleared(page);
  assert.match(page.byId('login-status').textContent, /session expired.*Sign in again/);
});

test('failed logout stays cleared, offers retry and login clears password/reset logout label', async () => {
  const page = await browser();
  page.overrides.set('/api/logout', () => { throw new Error('network unavailable'); });
  await page.byId('logout').listeners.click();
  assertCleared(page);
  assert.equal(page.byId('logout').textContent, 'Retry sign out');
  assert.equal(page.byId('logout').hidden, false);
  assert.match(page.byId('status').textContent, /server sign-out could not be confirmed/);
  page.overrides.delete('/api/logout');
  await page.byId('logout').listeners.click();
  assert.equal(page.byId('logout').hidden, true);
  page.byId('username').value = 'operator';
  page.byId('password').value = 'test-password';
  await page.byId('login-form').listeners.submit({ preventDefault() {} });
  assert.equal(page.byId('password').value, '');
  assert.equal(page.byId('logout').textContent, 'Sign out');
  assert.equal(page.byId('cycles').textContent, '77');
});
