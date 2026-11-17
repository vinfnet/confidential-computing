import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(scrypt);
const parameters = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const cookieName = '__Host-tailspin-session';
const sessionLifetime = 30 * 60 * 1000;
const attemptWindow = 15 * 60 * 1000;
const hashPattern = /^scrypt\$([a-f0-9]{32})\$([a-f0-9]{128})$/;

export async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 16 || password.length > 1024) {
    throw new Error('Operator password must contain between 16 and 1024 characters');
  }
  const salt = randomBytes(16).toString('hex');
  const key = await derive(password, salt, 64, parameters);
  try { return `scrypt$${salt}$${key.toString('hex')}`; }
  finally { key.fill(0); }
}

export function createOperatorAuth({ username, passwordHash, origin, onEvent = () => {}, now = Date.now }) {
  const verifier = hashPattern.exec(passwordHash || '');
  if (typeof username !== 'string' || !/^[a-zA-Z0-9_.@-]{1,128}$/.test(username) || !verifier) {
    throw new Error('A valid operator username and salted scrypt password verifier are required');
  }
  if (new URL(origin).origin !== origin || !origin.startsWith('https://')) {
    throw new Error('Operator authentication requires an exact HTTPS origin');
  }
  const expected = Buffer.from(verifier[2], 'hex');
  const sessions = new Map();
  const attempts = new Map();
  let pending = 0;
  const event = (name, outcome) => onEvent({ event: name, outcome });
  const tokenHash = (token) => createHash('sha256').update(token).digest('hex');
  const cookie = (token, age) =>
    `${cookieName}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
  const cleanup = () => {
    const time = now();
    for (const [id, session] of sessions) if (session.expiresAt <= time) sessions.delete(id);
    for (const [id, attempt] of attempts) if (attempt.expiresAt <= time) attempts.delete(id);
  };
  const sessionId = (req) => {
    const values = (req.headers.cookie || '').split(';').map((part) => part.trim())
      .filter((part) => part.startsWith(`${cookieName}=`));
    if (values.length !== 1) return null;
    const token = values[0].slice(cookieName.length + 1);
    return /^[a-zA-Z0-9_-]{43}$/.test(token) ? tokenHash(token) : null;
  };
  const session = (req) => {
    const id = sessionId(req);
    const value = sessions.get(id);
    if (value?.expiresAt > now()) return value;
    if (value) sessions.delete(id);
    return null;
  };
  const sameOrigin = (req, res, next) => {
    if (req.headers.origin !== origin) {
      event('operator_origin', 'rejected');
      return res.status(403).json({ error: 'origin_forbidden' });
    }
    if (!req.is('application/json')) return res.status(415).json({ error: 'json_required' });
    next();
  };
  const requireOperator = (req, res, next) => {
    const value = session(req);
    if (!value) {
      event('operator_auth', 'rejected');
      return res.status(401).json({ error: 'operator_sign_in_required' });
    }
    req.operator = { username: value.username };
    next();
  };
  const install = (app) => {
    app.get('/api/session', (req, res) => {
      const value = session(req);
      res.json(value ? { authenticated: true, user: value.username } : { authenticated: false });
    });
    app.post('/api/login', sameOrigin, async (req, res) => {
      if (!req.body || Array.isArray(req.body) ||
          Object.keys(req.body).some((key) => !['username', 'password'].includes(key)) ||
          typeof req.body.username !== 'string' || req.body.username.length > 128 ||
          typeof req.body.password !== 'string' || !req.body.password.length || req.body.password.length > 1024) {
        event('operator_login', 'rejected');
        return res.status(400).json({ error: 'invalid_login_body' });
      }
      cleanup();
      const address = req.socket.remoteAddress;
      let attempt = attempts.get(address);
      if (!attempt && attempts.size < 2048) {
        attempt = { count: 0, expiresAt: now() + attemptWindow };
        attempts.set(address, attempt);
      }
      if (!attempt || attempt.count >= 5) {
        event('operator_login_rate_limit', 'rejected');
        res.set('Retry-After', String(Math.ceil((attempt ? attempt.expiresAt - now() : attemptWindow) / 1000)));
        return res.status(429).json({ error: 'login_rate_limited' });
      }
      if (pending >= 4 || sessions.size >= 256) {
        event('operator_login_capacity', 'rejected');
        return res.status(503).json({ error: 'login_capacity_reached' });
      }
      attempt.count++;
      pending++;
      let actual;
      try {
        actual = await derive(req.body.password, verifier[1], 64, parameters);
        const valid = timingSafeEqual(actual, expected) && req.body.username === username;
        if (!valid) {
          event('operator_login', 'rejected');
          return res.status(401).json({ error: 'invalid_credentials' });
        }
        // Check capacity again after the asynchronous password derivation.
        if (sessions.size >= 256) {
          event('operator_login_capacity', 'rejected');
          return res.status(503).json({ error: 'login_capacity_reached' });
        }
        const previous = sessionId(req);
        if (previous) sessions.delete(previous);
        const token = randomBytes(32).toString('base64url');
        sessions.set(tokenHash(token), { username, expiresAt: now() + sessionLifetime });
        res.set('Set-Cookie', cookie(token, sessionLifetime / 1000));
        event('operator_login', 'accepted');
        res.json({ authenticated: true, user: username });
      } finally {
        actual?.fill(0);
        delete req.body.password;
        pending--;
      }
    });
    app.post('/api/logout', sameOrigin, (req, res) => {
      if (!req.body || Array.isArray(req.body) || Object.keys(req.body).length) {
        return res.status(400).json({ error: 'empty_action_body_required' });
      }
      const id = sessionId(req);
      if (id) sessions.delete(id);
      res.set('Set-Cookie', cookie('', 0));
      event('operator_logout', 'accepted');
      res.json({ authenticated: false });
    });
  };
  return { install, requireOperator };
}
