import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createOperatorAuth, hashPassword } from '../auth/operator.mjs';

const require = createRequire(new URL('../worker/package.json', import.meta.url));
const express = require('express');
const username = 'tailspin.operator';
const password = 'Test-only-operator-password-123!';
const passwordHash = await hashPassword(password);
const origin = 'https://tailspin.example:8443';

async function harness(t, options = {}) {
  const events = [];
  const auth = createOperatorAuth({
    username, passwordHash, origin, onEvent: (event) => events.push(event), ...options
  });
  const app = express();
  app.use(express.json({ limit: '4kb', strict: true }));
  app.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  auth.install(app);
  app.get('/protected', auth.requireOperator, (req, res) => res.json(req.operator));
  const server = createServer(app).listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  const url = `http://127.0.0.1:${server.address().port}`;
  const get = (route, cookie) => fetch(url + route, { headers: cookie ? { cookie } : {} });
  const post = (route, body, cookie, requestOrigin = origin) => fetch(url + route, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: requestOrigin, ...(cookie ? { Cookie: cookie } : {}) },
    body: JSON.stringify(body)
  });
  const login = (cookie) => post('/api/login', { username, password }, cookie);
  return { get, post, login, events };
}
const cookieOf = (response) => response.headers.get('set-cookie').split(';')[0];

test('password verifiers are independently salted and reject unsafe configuration', async () => {
  const second = await hashPassword(password);
  assert.notEqual(passwordHash, second);
  assert.doesNotMatch(passwordHash, /Test-only/);
  await assert.rejects(hashPassword('short'), /16/);
  assert.throws(() => createOperatorAuth({ username, passwordHash: 'plaintext', origin }), /scrypt/);
  assert.throws(() => createOperatorAuth({ username, passwordHash, origin: 'http://tailspin.example' }), /HTTPS/);
});

test('real password login creates a secure host-only cookie, with no token in JSON', async (t) => {
  const app = await harness(t);
  assert.equal((await app.get('/protected')).status, 401);
  const response = await app.login();
  assert.equal(response.status, 200);
  const header = response.headers.get('set-cookie');
  assert.match(header, /^__Host-tailspin-session=[\w-]{43};/);
  for (const flag of ['Path=/', 'HttpOnly', 'Secure', 'SameSite=Strict', 'Max-Age=1800']) {
    assert.ok(header.includes(flag), flag);
  }
  assert.ok(!header.includes('Domain='));
  assert.deepEqual(await response.json(), { authenticated: true, user: username });
  const cookie = cookieOf(response);
  assert.deepEqual(await (await app.get('/protected', cookie)).json(), { username });
  assert.deepEqual(await (await app.get('/api/session', cookie)).json(), { authenticated: true, user: username });
  assert.deepEqual(await (await app.get('/api/session', '__Host-tailspin-session=forged')).json(), { authenticated: false });
  assert.equal((await app.get('/protected', `${cookie}; ${cookie}`)).status, 401);
  assert.doesNotMatch(JSON.stringify(app.events), /Test-only|scrypt\$|session=/);
});

test('login rotates sessions; logout invalidates copied cookies immediately', async (t) => {
  const app = await harness(t);
  const old = cookieOf(await app.login());
  const current = cookieOf(await app.login(old));
  assert.notEqual(old, current);
  assert.equal((await app.get('/protected', old)).status, 401);
  const logout = await app.post('/api/logout', {}, current);
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
  assert.equal((await app.get('/protected', current)).status, 401);
});

test('session has an absolute thirty-minute deadline and cannot survive restart', async (t) => {
  let time = Date.now();
  const app = await harness(t, { now: () => time });
  const cookie = cookieOf(await app.login());
  time += 30 * 60 * 1000 - 1;
  assert.equal((await app.get('/protected', cookie)).status, 200);
  time++;
  assert.equal((await app.get('/protected', cookie)).status, 401);
  const restarted = await harness(t);
  assert.equal((await restarted.get('/protected', cookie)).status, 401);
});

test('login and logout reject cross-origin requests and invalid JSON shapes', async (t) => {
  const app = await harness(t);
  const credentials = { username, password };
  assert.equal((await app.post('/api/login', credentials, undefined, 'https://contoso.example')).status, 403);
  assert.equal((await app.post('/api/login', credentials, undefined, '')).status, 403);
  assert.equal((await app.post('/api/login', { ...credentials, role: 'admin' })).status, 400);
  assert.equal((await app.post('/api/login', { username, password: '' })).status, 400);
  const cookie = cookieOf(await app.login());
  assert.equal((await app.post('/api/logout', {}, cookie, 'https://contoso.example')).status, 403);
  assert.equal((await app.get('/protected', cookie)).status, 200);
  assert.equal((await app.post('/api/logout', { anything: true }, cookie)).status, 400);
});

test('wrong usernames and passwords have the same denial; brute force is bounded', async (t) => {
  let time = Date.now();
  const app = await harness(t, { now: () => time });
  for (let i = 0; i < 5; i++) {
    const response = await app.post('/api/login', { username: i % 2 ? username : 'unknown', password: 'wrong-password' });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: 'invalid_credentials' });
  }
  const blocked = await app.login();
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get('retry-after'), '900');
  time += 15 * 60 * 1000;
  assert.equal((await app.login()).status, 200);
});
