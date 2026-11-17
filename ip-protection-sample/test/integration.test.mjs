import { test } from 'node:test';
import assert from 'node:assert/strict';
import { constants, createCipheriv, generateKeyPairSync, publicEncrypt, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { request as httpsRequest } from 'node:https';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { encryptCommands } from '../tailspin/src/envelope.js';
import { Challenges, createTelemetryVerifier } from '../tailspin/src/security.js';
import { decryptEnvelope, ProtectedState } from '../worker/protection.mjs';
import { ephemeralTls } from '../tailspin/src/server.js';
import { hashPassword } from '../auth/operator.mjs';

const require = createRequire(new URL('../tailspin/package.json', import.meta.url));
const { SignJWT, createLocalJWKSet } = await import(pathToFileURL(require.resolve('jose')).href);
const vault = 'https://tailspin-test.vault.azure.net';
const keyName = 'contoso-robot';
const keyId = `${vault}/keys/${keyName}/${'a'.repeat(32)}`;
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });

test('Tailspin envelopes decrypt through the exact worker crypto contract', () => {
  const envelope = encryptCommands(pair.publicKey.export({ format: 'jwk' }), keyId, 17);
  const plaintext = decryptEnvelope(envelope, pair.privateKey.export({ format: 'jwk' }), vault, keyName);
  try {
    const command = JSON.parse(plaintext);
    assert.equal(command.fictional, true);
    assert.equal(command.product, 'Tailspin Skylark toy airplane');
    assert.equal(command.batch, 'DEMO-17');
    assert.equal(command.operation, '3D_PRINT_TOY');
    assert.equal(envelope.plaintext, undefined);
  } finally { plaintext.fill(0); }
});

test('recipient lock retains the exact Tailspin ciphertext but no plaintext', () => {
  const envelope = encryptCommands(pair.publicKey.export({ format: 'jwk' }), keyId, 18);
  const state = new ProtectedState();
  state.accept(envelope, decryptEnvelope(envelope, pair.privateKey.export({ format: 'jwk' }), vault, keyName));
  state.clear('Secure key release denied');
  assert.equal(state.snapshot().plaintext, null);
  assert.deepEqual(state.snapshot().envelope, envelope);
  assert.equal(state.snapshot().state, 'unavailable');
});

test('worker-shaped signed metrics satisfy Tailspin contract and cannot replay', async () => {
  const maa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const runtime = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const issuer = 'https://tailspin-test.westeurope.attest.azure.net';
  const hash = 'b'.repeat(64);
  const challenges = new Challenges();
  const runtimeJwk = { ...runtime.publicKey.export({ format: 'jwk' }), kid: 'robot-telemetry', alg: 'RS256', use: 'sig' };
  const evidence = await new SignJWT({
    'x-ms-attestation-type': 'sevsnpvm',
    'x-ms-compliance-status': 'azure-compliant-uvm',
    'x-ms-sevsnpvm-is-debuggable': false,
    'x-ms-sevsnpvm-hostdata': hash,
    'x-ms-runtime': { keys: [runtimeJwk] }
  }).setProtectedHeader({ alg: 'RS256', kid: 'test-maa' }).setIssuer(issuer)
    .setIssuedAt().setExpirationTime('1h').sign(maa.privateKey);
  const { nonce } = challenges.issue();
  const metrics = {
    state: 'protected', latencyMs: 42.5, uptimeSeconds: Math.floor(process.uptime()),
    completedCycles: 3, defectRate: 0.01
  };
  const proof = await new SignJWT({ nonce, metrics })
    .setProtectedHeader({ alg: 'RS256', kid: runtimeJwk.kid }).setIssuedAt()
    .setExpirationTime('45s').sign(runtime.privateKey);
  const verify = createTelemetryVerifier({ maaEndpoint: issuer, workerPolicyHash: hash }, challenges, {
    jwks: createLocalJWKSet({ keys: [{ ...maa.publicKey.export({ format: 'jwk' }), kid: 'test-maa', alg: 'RS256' }] })
  });
  assert.deepEqual(await verify({ attestationToken: evidence, proof }), metrics);
  await assert.rejects(verify({ attestationToken: evidence, proof }), /nonce_expired_or_replayed/);
});

function bootstrapHarness(deny = false) {
  const transportName = 'tailspin-transport';
  const tlsKey = 'test-only-private-tls-material';
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dek, iv);
  const envelope = {
    keyId: `${vault}/keys/${transportName}/${'a'.repeat(32)}`,
    algorithm: 'A256GCM',
    wrappedKey: publicEncrypt({
      key: pair.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'
    }, dek).toString('base64'),
    iv: iv.toString('base64'), aad: '',
    ciphertext: Buffer.concat([cipher.update(tlsKey), cipher.final()]).toString('base64'),
    tag: cipher.getAuthTag().toString('base64')
  };
  dek.fill(0);
  const helper = new URL('../worker/protection.mjs', import.meta.url).href;
  const source = readFileSync(new URL('../infra/bootstrap.mjs', import.meta.url), 'utf8')
    .replace("'./transport.mjs'", JSON.stringify(helper));
  const application = `export function start() {
    if (Buffer.from(process.env.TLS_KEY_B64, 'base64').toString() !== ${JSON.stringify(tlsKey)})
      throw new Error('TLS material was not decrypted before application startup');
    console.log('APPLICATION_STARTED');
  }`;
  const setup = `
    globalThis.setTimeout = callback => { queueMicrotask(callback); };
    globalThis.fetch = async () => ({
      ok: ${!deny}, status: ${deny ? 403 : 200},
      json: async () => ({ key: ${JSON.stringify(pair.privateKey.export({ format: 'jwk' }))} })
    });
  `;
  return spawnSync(process.execPath, ['--input-type=module', '--eval', setup + source], {
    encoding: 'utf8',
    env: {
      ...process.env, TLS_ENVELOPE: JSON.stringify(envelope), TLS_KEY_NAME: transportName,
      VAULT_URL: vault, MAA_ENDPOINT: 'https://test.attest.azure.net',
      APPLICATION_ENTRYPOINT: `data:text/javascript,${encodeURIComponent(application)}`
    },
    timeout: 10_000
  });
}

test('TLS bootstrap decrypts before invoking the controller exported start function', () => {
  const result = bootstrapHarness();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /APPLICATION_STARTED/);
});

test('TLS bootstrap fails closed when secure key release is denied', () => {
  const result = bootstrapHarness(true);
  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout, /APPLICATION_STARTED/);
  assert.match(result.stderr, /Transport SKR returned HTTP 403/);
});

test('real worker HTTPS serves ciphertext-only state and rejects anonymous plaintext access', async () => {
  const tls = await ephemeralTls({ tailspinUrl: 'https://localhost' });
  const workerUrl = new URL('../worker/server.mjs', import.meta.url).href;
  const script = `
    import https from 'node:https';
    const createServer = https.createServer;
    https.createServer = (...args) => {
      const server = createServer(...args);
      const listen = server.listen.bind(server);
      server.listen = (_port, _host, ready) => listen(0, '127.0.0.1', () => {
        console.log('READY:' + server.address().port);
        ready();
      });
      return server;
    };
    await import(${JSON.stringify(workerUrl)});
  `;
  const child = spawn(process.execPath, ['--input-type=module', '--eval', script], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      OPERATOR_USERNAME: 'tailspin.test',
      OPERATOR_PASSWORD_HASH: await hashPassword('Test-only-worker-password'),
      WORKER_URL: 'https://worker.example:8443',
      TAILSPIN_URL: 'https://127.0.0.1:1', VAULT_URL: vault,
      MAA_ENDPOINT: 'https://test.attest.azure.net',
      TLS_CERT_B64: tls.cert.toString('base64'), TLS_KEY_B64: tls.key.toString('base64')
    }
  });
  let diagnostics = '';
  child.stderr.on('data', chunk => { diagnostics += chunk; });
  try {
    const port = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Worker startup timeout: ${diagnostics}`)), 10_000);
      let output = '';
      child.stdout.on('data', chunk => {
        output += chunk;
        const match = /READY:(\d+)/.exec(output);
        if (match) { clearTimeout(timer); resolve(Number(match[1])); }
      });
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', code => { clearTimeout(timer); reject(new Error(`Worker exited ${code}: ${diagnostics}`)); });
    });
    const get = (pathname, { method = 'GET', headers = {}, body } = {}) => new Promise((resolve, reject) => {
      const req = httpsRequest({
        host: '127.0.0.1', port, path: pathname, ca: tls.cert, method, headers
      }, response => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', chunk => { body += chunk; });
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body }));
      });
      req.on('error', reject);
      req.end(body);
    });
    const health = await get('/api/health');
    assert.equal(health.status, 200);
    assert.equal(JSON.parse(health.body).state, 'unavailable');
    const ciphertext = await get('/api/ciphertext');
    assert.equal(ciphertext.status, 200);
    assert.equal(Object.hasOwn(JSON.parse(ciphertext.body), 'plaintext'), false);
    assert.equal(ciphertext.headers['cache-control'], 'no-store');
    const commands = await get('/api/commands');
    assert.equal(commands.status, 401);
    assert.equal(Object.hasOwn(JSON.parse(commands.body), 'plaintext'), false);
    const page = await get('/');
    assert.equal(page.status, 200);
    assert.match(page.body, /Encrypted command envelope/);
    assert.match(page.body, /Plaintext is not available/);
    assert.match(page.body, /login-form/);
    assert.doesNotMatch(page.body, /msal/);
    assert.equal((await get('/ui/preferences.js')).status, 200);
    assert.equal((await get('/ui/preferences.css')).status, 200);
    const login = await get('/api/login', {
      method: 'POST', headers: { Origin: 'https://worker.example:8443', 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'tailspin.test', password: 'Test-only-worker-password' })
    });
    assert.equal(login.status, 200);
    const cookie = login.headers['set-cookie'][0].split(';')[0];
    assert.equal((await get('/api/commands', { headers: { Cookie: cookie } })).status, 200);
    assert.equal((await get('/api/logout', {
      method: 'POST', headers: { Cookie: cookie, Origin: 'https://worker.example:8443', 'Content-Type': 'application/json' }, body: '{}'
    })).status, 200);
    assert.equal((await get('/api/commands', { headers: { Cookie: cookie } })).status, 401);
  } finally { child.kill(); }
});
