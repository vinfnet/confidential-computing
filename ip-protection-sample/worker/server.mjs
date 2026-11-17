import express from 'express';
import https from 'node:https';
import { generateKeyPairSync } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, SignJWT } from 'jose';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { ProtectedState, decryptEnvelope } from './protection.mjs';
import { createOperatorAuth } from '../auth/operator.mjs';
import { installDemoUi } from '../ui/server.mjs';

const required = ['OPERATOR_USERNAME', 'OPERATOR_PASSWORD_HASH', 'WORKER_URL', 'TAILSPIN_URL',
  'VAULT_URL', 'MAA_ENDPOINT', 'TLS_CERT_B64', 'TLS_KEY_B64'];
for (const name of required) if (!process.env[name]) throw new Error(`Missing ${name}`);
const env = process.env;
const keyName = env.WORKER_KEY_NAME || 'contoso-robot';
const state = new ProtectedState();
const app = express();
const dirname = path.dirname(fileURLToPath(import.meta.url));
const maaUrl = env.MAA_ENDPOINT.startsWith('https://') ? env.MAA_ENDPOINT : `https://${env.MAA_ENDPOINT}`;
const maaKeys = createRemoteJWKSet(new URL(`${maaUrl}/certs`));
const operatorAuth = createOperatorAuth({
  username: env.OPERATOR_USERNAME, passwordHash: env.OPERATOR_PASSWORD_HASH, origin: env.WORKER_URL,
  onEvent: (record) => console.log(JSON.stringify(record))
});
const telemetryKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = { ...telemetryKey.publicKey.export({ format: 'jwk' }), kid: 'robot-telemetry', alg: 'RS256', use: 'sig' };
let completedCycles = 0;
let latencyMs = 0;
let telemetryError = null;

async function json(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error(`Dependency ${new URL(url).pathname} returned HTTP ${response.status}`);
  return response.json();
}
async function sidecar(route, body) {
  return json(`http://127.0.0.1:8080/${route}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
}
async function attest() {
  const result = await sidecar('attest/maa', {
    maa_endpoint: new URL(maaUrl).hostname,
    runtime_data: Buffer.from(JSON.stringify({ keys: [publicJwk] })).toString('base64')
  });
  const { payload } = await jwtVerify(result.token, maaKeys, { issuer: maaUrl, maxTokenAge: '90s' });
  if (payload['x-ms-attestation-type'] !== 'sevsnpvm' ||
      payload['x-ms-compliance-status'] !== 'azure-compliant-uvm' ||
      ![false, 'false'].includes(payload['x-ms-sevsnpvm-is-debuggable'])) {
    throw new Error('Hardware attestation requirements not satisfied');
  }
  return result.token;
}
async function cycle() {
  const start = performance.now();
  let token;
  try {
    // Hide the previous plaintext before awaiting any dependency, including a hung one.
    state.clear('Refreshing hardware attestation and key access');
    const envelope = await json(`${env.TAILSPIN_URL}/api/envelope`);
    state.envelope = envelope;
    token = await attest();
    const released = await sidecar('key/release', {
      maa_endpoint: new URL(maaUrl).hostname,
      akv_endpoint: new URL(env.VAULT_URL).hostname,
      kid: envelope.keyId.split('/').slice(-2).join('/')
    });
    const jwk = typeof released.key === 'string' ? JSON.parse(released.key) : released.key;
    try {
      state.accept(envelope, decryptEnvelope(envelope, jwk, env.VAULT_URL, keyName));
    } finally {
      // Discard private fields even when authenticated decryption rejects the envelope.
      for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) delete jwk[field];
    }
    completedCycles++;
    latencyMs = performance.now() - start;
  } catch (error) {
    state.clear(error.message);
    console.error(JSON.stringify({ event: 'protection-unavailable', reason: error.message }));
  }
  try {
    token ??= await attest();
    const { nonce } = await json(`${env.TAILSPIN_URL}/api/challenge`);
    const proof = await new SignJWT({
      nonce, metrics: { state: state.snapshot().state, latencyMs, uptimeSeconds: Math.floor(process.uptime()),
        completedCycles, defectRate: Number((Math.random() * 0.02).toFixed(4)) }
    }).setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid }).setIssuedAt().setExpirationTime('45s')
      .sign(telemetryKey.privateKey);
    await json(`${env.TAILSPIN_URL}/api/telemetry`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attestationToken: token, proof })
    });
    telemetryError = null;
  } catch (error) {
    telemetryError = error.message;
    console.error(JSON.stringify({ event: 'telemetry-failed', reason: error.message }));
  }
  setTimeout(cycle, 3000);
}
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
  });
  next();
});
app.use(express.json({ limit: '4kb', strict: true }));
operatorAuth.install(app);
app.get('/api/config', (_req, res) => res.json({ authMode: 'password' }));
app.get('/api/health', (_req, res) => res.json({ service: 'contoso-robot', state: state.snapshot().state }));
app.get('/api/ciphertext', (_req, res) => {
  const { plaintext: _plaintext, ...safe } = state.snapshot();
  res.json({ ...safe, telemetryError });
});
app.get('/api/commands', operatorAuth.requireOperator, (_req, res) => res.json(state.snapshot()));
installDemoUi(app);
app.use(express.static(path.join(dirname, 'public')));
app.use((error, _req, res, _next) => {
  console.error(JSON.stringify({ event: 'request-error', message: error.message }));
  const status = error.type === 'entity.too.large' ? 413 : error.type === 'entity.parse.failed' ? 400 : 500;
  res.status(status).json({ error: status === 413 ? 'payload_too_large' : status === 400 ? 'invalid_json' : 'Request failed' });
});
https.createServer({
  key: Buffer.from(env.TLS_KEY_B64, 'base64'), cert: Buffer.from(env.TLS_CERT_B64, 'base64'),
  minVersion: 'TLSv1.2'
}, app).listen(8443, '0.0.0.0', () => { cycle(); });
