import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from '../src/app.js';
import { AppError, Challenges } from '../src/security.js';

const config = {
  tailspinUrl: 'https://tailspin.example',
  workerUrl: 'https://worker.example', testHttp: true
};

async function fixture(t, overrides = {}) {
  let actionCalls = 0;
  const { app, security } = createApp(config, {
    authenticate: async (header) => { if (header !== 'Bearer accepted') throw new AppError(401, 'unauthorized'); return { oid: 'operator' }; },
    gate: { ready: () => true, require: async () => {} },
    envelopes: { get: async () => ({ algorithm: 'A256GCM', ciphertext: 'encrypted-test-bytes' }) },
    challenges: new Challenges(),
    verifyTelemetry: async () => ({ state: 'protected', latencyMs: 13, uptimeSeconds: 20, completedCycles: 5, defectRate: 0 }),
    actions: Object.fromEntries(['deploy', 'restart', 'revoke'].map((action) => [action, async () => {
      actionCalls++;
      return { status: 'accepted', operation: action };
    }])),
    ...overrides
  });
  // The fixture uses explicit localhost-only test HTTP; production server.js uses HTTPS by default.
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    request: (url, options) => fetch(`${base}${url}`, options),
    calls: () => actionCalls, security
  };
}
const auth = { authorization: 'Bearer accepted' };
const management = { ...auth, origin: config.tailspinUrl, 'content-type': 'application/json' };

test('public health/config/encrypted envelope and password form; dashboard requires auth', async (t) => {
  const { request } = await fixture(t);
  const health = await request('/api/health');
  assert.deepEqual(await health.json(), { ready: true });
  const cfg = await (await request('/api/config')).json();
  assert.deepEqual(Object.keys(cfg).sort(), ['tailspinUrl', 'workerUrl']);
  assert.equal((await request('/api/dashboard')).status, 401);
  const envelope = await (await request('/api/envelope')).json();
  assert.deepEqual(envelope, { algorithm: 'A256GCM', ciphertext: 'encrypted-test-bytes' });
  const page = await request('/');
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.ok(html.includes('Worker-reported metrics. Real security.'));
  assert.ok(html.includes('only defect rate is synthetic'));
  assert.ok(html.includes('Defect rate (synthetic)'));
  assert.ok(html.includes('autocomplete="username"'));
  assert.ok(html.includes('type="password" autocomplete="current-password"'));
  assert.ok(!html.includes('msal'));
  assert.ok(!page.headers.get('content-security-policy').includes('microsoftonline'));
  assert.ok(page.headers.get('content-security-policy').includes("script-src 'self'"));
  assert.equal(page.headers.get('cache-control'), 'no-store');
  assert.equal((await request('/vendor/msal-browser.min.js')).status, 404);
});

test('no fabricated availability or uptime before actual verified samples; records and events bounded to 500', async (t) => {
  const { request, security } = await fixture(t);
  let dashboard = await (await request('/api/dashboard', { headers: auth })).json();
  assert.equal(dashboard.availability.status, 'unknown');
  assert.equal(dashboard.availability.protectedSamplePercent, null);
  assert.equal(dashboard.heartbeat.lastSeen, null);
  assert.equal(dashboard.records.length, 0);
  for (let i = 0; i < 503; i++) {
    const response = await request('/api/telemetry', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
    });
    assert.equal(response.status, 202);
  }
  for (let i = 0; i < 503; i++) security('safe_event', 'verified');
  dashboard = await (await request('/api/dashboard', { headers: auth })).json();
  assert.equal(dashboard.records.length, 500);
  assert.equal(dashboard.securityEvents.length, 500);
  assert.equal(dashboard.availability.protectedSamplePercent, 100);
  assert.equal(dashboard.heartbeat.status, 'receiving');
  assert.equal('syntheticPerformance' in dashboard, false);
  assert.deepEqual(dashboard.metricProvenance, {
    state: 'worker-reported', latencyMs: 'worker-reported-measured',
    uptimeSeconds: 'worker-reported-process', completedCycles: 'worker-reported-count', defectRate: 'synthetic'
  });
  assert.ok(dashboard.metricAssurance.includes('not independently proven'));
});

test('management auth, exact Origin, content type and body enforcement, real pending response', async (t) => {
  const { request, calls } = await fixture(t);
  assert.equal((await request('/api/actions/deploy', { method: 'POST', body: '{}' })).status, 401);
  assert.equal((await request('/api/actions/deploy', {
    method: 'POST', headers: { ...management, origin: 'https://evil.example' }, body: '{}'
  })).status, 403);
  assert.equal((await request('/api/actions/restart', {
    method: 'POST', headers: { ...auth, origin: config.tailspinUrl }, body: '{}'
  })).status, 415);
  assert.equal((await request('/api/actions/restart', {
    method: 'POST', headers: management, body: '{"resourceId":"attacker"}'
  })).status, 400);
  assert.equal(calls(), 0);
  for (const action of ['deploy', 'restart', 'revoke']) {
    const response = await request(`/api/actions/${action}`, { method: 'POST', headers: management, body: '{}' });
    assert.equal(response.status, 202);
    assert.deepEqual(await response.json(), { operation: action, status: 'accepted' });
  }
  assert.equal(calls(), 3);
});

test('gate failure blocks all sensitive endpoints while health/config stay minimal', async (t) => {
  const { request, calls } = await fixture(t, {
    gate: { ready: () => false, async require() { throw new AppError(503, 'self_release_unavailable'); } }
  });
  const health = await request('/api/health');
  assert.equal(health.status, 503);
  assert.deepEqual(await health.json(), { ready: false });
  assert.equal((await request('/api/config')).status, 200);
  for (const url of ['/api/envelope', '/api/challenge']) {
    assert.equal((await request(url, { headers: auth })).status, 503);
  }
  const dashboard = await request('/api/dashboard', { headers: auth });
  assert.equal(dashboard.status, 200);
  assert.equal((await dashboard.json()).selfReleaseReady, false);
  assert.equal((await request('/')).status, 200);
  assert.equal((await request('/api/dashboard')).status, 401);
  assert.equal((await request('/api/telemetry', { method: 'POST', headers: management, body: '{}' })).status, 503);
  assert.equal((await request('/api/actions/revoke', { method: 'POST', headers: management, body: '{}' })).status, 503);
  assert.equal(calls(), 0);
});

test('malformed/oversized bodies, telemetry rejection and secret dependency errors are sanitized', async (t) => {
  const secret = 'SECRET-TOKEN-COMMAND-PRIVATE-JWK';
  const { request } = await fixture(t, {
    verifyTelemetry: async () => { throw new AppError(401, 'invalid_attestation'); },
    envelopes: { get: async () => { throw new Error(secret); } }
  });
  assert.equal((await request('/api/telemetry', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{invalid'
  })).status, 400);
  assert.equal((await request('/api/telemetry', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ data: 'x'.repeat(80000) })
  })).status, 413);
  const response = await request('/api/telemetry', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
  });
  assert.equal(response.status, 401);
  const encrypted = await request('/api/envelope');
  assert.equal(encrypted.status, 503);
  assert.ok(!(await encrypted.text()).includes(secret));
  const dashboard = await (await request('/api/dashboard', { headers: auth })).json();
  assert.equal(dashboard.records.length, 0);
  assert.ok(dashboard.securityEvents.some((e) => e.outcome === 'rejected'));
  assert.ok(dashboard.securityEvents.some((e) => e.outcome === 'rejected' && e.reason === 'invalid_attestation'));
  assert.ok(dashboard.securityEvents.some((e) => e.reason === 'invalid_json'));
  assert.ok(!dashboard.securityEvents.some((e) => e.event === 'worker_attestation_and_proof' && e.outcome === 'verified'));
  assert.ok(!JSON.stringify(dashboard).includes(secret));
});

test('unexpected verification failure is sanitized, not recorded as successful attestation', async (t) => {
  const { request } = await fixture(t, {
    verifyTelemetry: async () => { throw new Error('verified SECRET-TOKEN forged text'); }
  });
  const response = await request('/api/telemetry', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
  });
  assert.equal(response.status, 503);
  const dashboard = await (await request('/api/dashboard', { headers: auth })).json();
  assert.equal(dashboard.records.length, 0);
  assert.equal(dashboard.heartbeat.lastSeen, null);
  assert.deepEqual(dashboard.securityEvents.map(({ event, outcome, reason }) => ({ event, outcome, reason })), [
    { event: 'worker_attestation_and_proof', outcome: 'rejected', reason: 'evidence_verification_unavailable' }
  ]);
  assert.ok(!JSON.stringify(dashboard).includes('SECRET-TOKEN'));
});
