import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { createOperatorAuth, hashPassword } from '../../auth/operator.mjs';
import { createApp } from '../src/app.js';
import { AppError, Challenges } from '../src/security.js';

const username = 'test-operator';
const password = `test-only-${randomBytes(24).toString('base64url')}`;
const passwordHash = await hashPassword(password);
const origin = 'https://tailspin.example';

async function fixture(t, { ready = true } = {}) {
  let time = Date.now();
  let report = () => {};
  const operatorAuth = createOperatorAuth({
    username, passwordHash, origin, now: () => time,
    onEvent: ({ event, outcome }) => report(event, outcome)
  });
  const { app, security } = createApp({
    tailspinUrl: origin, workerUrl: 'https://worker.example', testHttp: true
  }, {
    operatorAuth,
    gate: {
      ready: () => ready,
      require: async () => { if (!ready) throw new AppError(503, 'self_release_unavailable'); }
    },
    envelopes: { get: async () => ({ ciphertext: 'encrypted-only' }) },
    challenges: new Challenges(),
    verifyTelemetry: async () => { throw new AppError(401, 'invalid_attestation'); },
    actions: Object.fromEntries(['deploy', 'restart', 'revoke'].map((operation) => [
      operation, async () => ({ status: 'accepted', operation })
    ])),
    now: () => time
  });
  report = security;
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (url, options) => fetch(`${base}${url}`, options);
  const post = (url, body, cookie, requestOrigin = origin) => request(url, {
    method: 'POST', headers: {
      'content-type': 'application/json', origin: requestOrigin, ...(cookie ? { cookie } : {})
    }, body: JSON.stringify(body)
  });
  const login = async (cookie) => {
    const response = await post('/api/login', { username, password }, cookie);
    assert.equal(response.status, 200);
    return response.headers.get('set-cookie').split(';')[0];
  };
  return { request, post, login, advance: (ms) => { time += ms; } };
}

test('real password login sets secure cookie; cookie gates dashboard/actions, not public worker routes', async (t) => {
  const { request, post, login } = await fixture(t);
  assert.deepEqual(await (await request('/api/session')).json(), { authenticated: false });
  assert.equal((await request('/api/dashboard')).status, 401);
  assert.equal((await request('/api/dashboard', {
    headers: { authorization: 'Bearer not-an-operator-session' }
  })).status, 401);
  assert.equal((await post('/api/login', { username, password: 'wrong-password' })).status, 401);
  assert.equal((await post('/api/login', { username: 'unknown', password })).status, 401);
  const response = await post('/api/login', { username, password });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { authenticated: true, user: username });
  const setCookie = response.headers.get('set-cookie');
  for (const flag of ['Path=/', 'HttpOnly', 'Secure', 'SameSite=Strict', 'Max-Age=1800']) {
    assert.ok(setCookie.includes(flag));
  }
  assert.ok(!setCookie.includes('Domain='));
  const cookie = setCookie.split(';')[0];
  assert.match(cookie, /^__Host-tailspin-session=[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(await (await request('/api/session', { headers: { cookie } })).json(), {
    authenticated: true, user: username
  });
  const dashboard = await request('/api/dashboard', { headers: { cookie } });
  assert.equal(dashboard.status, 200);
  const data = await dashboard.json();
  assert.ok(data.securityEvents.some((event) => event.event === 'operator_login' && event.outcome === 'accepted'));
  for (const forbidden of [password, passwordHash, cookie.split('=')[1]]) {
    assert.ok(!JSON.stringify(data).includes(forbidden));
  }
  assert.deepEqual(await (await request('/api/config')).json(), {
    tailspinUrl: origin, workerUrl: 'https://worker.example'
  });
  assert.equal((await request('/api/challenge')).status, 200);
  assert.equal((await request('/api/envelope')).status, 200);
  assert.equal((await post('/api/telemetry', {})).status, 401);
  for (const action of ['deploy', 'restart', 'revoke']) {
    assert.equal((await post(`/api/actions/${action}`, {}, cookie)).status, 202);
  }
  const replacement = await login(cookie);
  assert.notEqual(replacement, cookie);
  assert.equal((await request('/api/dashboard', { headers: { cookie } })).status, 401);
  assert.equal((await request('/api/dashboard', { headers: { cookie: replacement } })).status, 200);
});

test('session origin/JSON/body restrictions, invalid cookies, logout and thirty-minute expiry', async (t) => {
  const { request, post, login, advance } = await fixture(t);
  assert.equal((await post('/api/login', { username, password }, null, 'https://evil.example')).status, 403);
  assert.equal((await request('/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, password })
  })).status, 403);
  assert.equal((await request('/api/login', {
    method: 'POST', headers: { origin }, body: JSON.stringify({ username, password })
  })).status, 415);
  assert.equal((await post('/api/login', { username, password, bypass: true })).status, 400);
  const cookie = await login();
  assert.equal((await post('/api/actions/restart', {}, cookie, 'https://evil.example')).status, 403);
  assert.equal((await post('/api/actions/restart', { resourceId: 'other' }, cookie)).status, 400);
  assert.equal((await post('/api/logout', {}, cookie, 'https://evil.example')).status, 403);
  assert.equal((await post('/api/logout', { extra: true }, cookie)).status, 400);
  assert.equal((await request('/api/dashboard', { headers: { cookie: `${cookie}; ${cookie}` } })).status, 401);
  assert.equal((await request('/api/dashboard', {
    headers: { cookie: `__Host-tailspin-session=${randomBytes(32).toString('base64url')}` }
  })).status, 401);
  const logout = await post('/api/logout', {}, cookie);
  assert.equal(logout.status, 200);
  assert.ok(logout.headers.get('set-cookie').includes('Max-Age=0'));
  assert.equal((await request('/api/dashboard', { headers: { cookie } })).status, 401);
  assert.deepEqual(await (await request('/api/session', { headers: { cookie } })).json(), { authenticated: false });
  const expiring = await login();
  advance(30 * 60 * 1000);
  assert.equal((await request('/api/dashboard', { headers: { cookie: expiring } })).status, 401);
  assert.equal((await post('/api/actions/revoke', {}, expiring)).status, 401);
});

test('login is rate-limited and remains available during a failed release gate', async (t) => {
  const { request, post, login } = await fixture(t, { ready: false });
  const cookie = await login();
  assert.equal((await request('/api/dashboard', { headers: { cookie } })).status, 200);
  assert.equal((await post('/api/actions/restart', {}, cookie)).status, 503);
  assert.equal((await post('/api/logout', {}, cookie)).status, 200);
  for (let attempt = 0; attempt < 4; attempt++) {
    assert.equal((await post('/api/login', { username, password: 'wrong' })).status, 401);
  }
  const limited = await post('/api/login', { username, password });
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get('retry-after')) > 0);
});
