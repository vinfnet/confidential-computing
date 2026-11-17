import test from 'node:test';
import assert from 'node:assert/strict';
import { OperatorSession } from '../public/session.js';

const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

test('default browser fetch retains the global receiver for restore, login, protected requests and logout', async (t) => {
  const requests = [];
  let authenticated = false;
  t.mock.method(globalThis, 'fetch', async function (url, options) {
    assert.equal(this, globalThis, 'native Window.fetch requires the Window receiver');
    requests.push({ url, options });
    if (url === '/api/login') authenticated = true;
    if (url === '/api/logout') authenticated = false;
    return response({ authenticated, ...(authenticated ? { user: 'operator' } : {}) });
  });
  const session = new OperatorSession();
  await session.restore();
  assert.equal(session.user, null);
  await session.login('operator', 'test-password');
  await session.request('/api/dashboard');
  await session.logout();
  assert.equal(session.user, null);
  assert.deepEqual(requests.map(({ url }) => url), [
    '/api/session', '/api/login', '/api/session', '/api/dashboard', '/api/logout'
  ]);
  assert.ok(requests.every(({ options }) => options.credentials === 'same-origin'));
});

test('browser logs in with same-origin cookies and clears on logout without token storage', async () => {
  const requests = [];
  const changes = [];
  const session = new OperatorSession({
    onChange: (user) => changes.push(user),
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      if (url === '/api/session') return response({ authenticated: true, user: 'operator' });
      return response({ authenticated: url !== '/api/logout' });
    }
  });
  await session.login('operator', 'test-password');
  assert.equal(session.user, 'operator');
  assert.deepEqual(JSON.parse(requests[0].options.body), { username: 'operator', password: 'test-password' });
  assert.ok(requests.every(({ options }) => options.credentials === 'same-origin' && options.cache === 'no-store'));
  assert.ok(requests.every(({ options }) => !options.headers?.authorization));
  await session.logout();
  assert.equal(session.user, null);
  assert.deepEqual(changes, ['operator', null]);
  assert.deepEqual(JSON.parse(requests.at(-1).options.body), {});
});

test('logout immediately clears the session, aborts requests and rejects late dashboard/action responses', async () => {
  const dashboard = deferred();
  const action = deferred();
  const logout = deferred();
  const signals = [];
  const session = new OperatorSession({
    fetchImpl: (url, options) => {
      signals.push(options.signal);
      return url === '/api/dashboard' ? dashboard.promise :
        url === '/api/logout' ? logout.promise : action.promise;
    }
  });
  session.user = 'operator';
  const dashboardResult = session.request('/api/dashboard');
  const actionResult = session.request('/api/actions/restart', { method: 'POST' });
  const dashboardRejected = assert.rejects(dashboardResult, /Session changed/);
  const actionRejected = assert.rejects(actionResult, /Session changed/);
  const logoutResult = session.logout();
  assert.equal(session.user, null);
  assert.equal(signals[0].aborted, true);
  assert.equal(signals[1].aborted, true);
  dashboard.resolve(response({ records: ['protected-data'] }));
  action.resolve(response({ status: 'accepted' }));
  logout.resolve(response({ authenticated: false }));
  await Promise.all([dashboardRejected, actionRejected, logoutResult]);
  assert.equal(session.requests.size, 0);
});

test('401 explicitly expires the browser session and rejects protected requests until login', async () => {
  let expired = 0;
  const session = new OperatorSession({
    fetchImpl: async () => response({ error: 'operator_sign_in_required' }, 401),
    onExpired: () => expired++
  });
  session.user = 'operator';
  await assert.rejects(session.request('/api/dashboard'), /session expired/);
  assert.equal(session.user, null);
  assert.equal(expired, 1);
  await assert.rejects(session.request('/api/actions/deploy'), /Sign in/);
});

test('late session discovery or login cannot restore a signed-out browser; failed logout stays cleared', async () => {
  for (const operation of ['restore', 'login']) {
    const pending = deferred();
    const session = new OperatorSession({
      fetchImpl: async (url) => url === '/api/logout' ? response({ authenticated: false }) : pending.promise
    });
    const result = operation === 'restore' ? session.restore() : session.login('operator', 'test-password');
    const rejected = assert.rejects(result, /Session changed/);
    await session.logout();
    pending.resolve(response({ authenticated: true, user: 'operator' }));
    await rejected;
    assert.equal(session.user, null);
  }
  const failed = new OperatorSession({ fetchImpl: async () => { throw new Error('network unavailable'); } });
  failed.user = 'operator';
  await assert.rejects(failed.logout(), /network unavailable/);
  assert.equal(failed.user, null);
});
