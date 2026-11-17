import test from 'node:test';
import assert from 'node:assert/strict';
import {
  constants, createDecipheriv, generateKeyPairSync, privateDecrypt, randomBytes
} from 'node:crypto';
import { SignJWT } from 'jose';
import {
  AppError, Challenges, createGate, createTelemetryVerifier,
  validateMetrics, validateReleasedKey
} from '../src/security.js';
import { createEnvelopeService, encryptCommands } from '../src/envelope.js';
import { createActions, validateWorkerTemplate } from '../src/actions.js';
import { loadConfig } from '../src/config.js';

const tenantId = '11111111-1111-4111-8111-111111111111';
const oid = '33333333-3333-4333-8333-333333333333';
const config = {
  tailspinUrl: 'https://tailspin.example', workerUrl: 'https://contoso.example',
  vaultUrl: 'https://example.vault.azure.net', maaEndpoint: 'https://example.attest.azure.net',
  selfKeyName: 'tailspin-control', workerKeyName: 'contoso-robot', workerPolicyHash: 'ab'.repeat(32),
  workerResourceId: `/subscriptions/${tenantId}/resourceGroups/demo/providers/Microsoft.ContainerInstance/containerGroups/contoso`,
  workerApiVersion: '2023-05-01', workerTemplatePath: 'approved.json'
};
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const runtime = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = rsa.publicKey.export({ format: 'jwk' });
const runtimeJwk = runtime.publicKey.export({ format: 'jwk' });
const keyId = `${config.vaultUrl}/keys/contoso-robot/v1`;
const current = Math.floor(Date.now() / 1000);
const clock = () => current * 1000;
const metrics = { state: 'protected', latencyMs: 42.5, uptimeSeconds: 30, completedCycles: 9, defectRate: 0.02 };
const sign = (body, key = rsa.privateKey) => new SignJWT(body).setProtectedHeader({ alg: 'RS256' }).sign(key);
const maaClaims = () => ({
  iss: config.maaEndpoint, iat: current, exp: current + 90,
  'x-ms-compliance-status': 'azure-compliant-uvm',
  'x-ms-sevsnpvm-is-debuggable': false,
  'x-ms-sevsnpvm-hostdata': config.workerPolicyHash,
  'x-ms-attestation-type': 'sevsnpvm',
  'x-ms-runtime': { keys: [runtimeJwk] }
});
const approved = () => ({
  location: 'eastus',
  properties: { sku: 'Confidential', confidentialComputeProperties: { ccePolicy: 'exact-generated-policy' } }
});
const fails = (code) => (error) => error instanceof AppError && error.code === code;

test('real RSA-OAEP SHA256 and AES-GCM roundtrip, metadata AAD and tamper rejection', () => {
  const envelope = encryptCommands(publicJwk, keyId, 17);
  assert.deepEqual(Object.keys(envelope).sort(), [
    'aad', 'algorithm', 'ciphertext', 'issuedAt', 'iv', 'keyId', 'sequence', 'tag', 'wrappedKey'
  ]);
  assert.equal(envelope.algorithm, 'A256GCM');
  const dek = privateDecrypt({
    key: rsa.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'
  }, Buffer.from(envelope.wrappedKey, 'base64'));
  assert.equal(dek.length, 32);
  const decrypt = (item) => {
    const cipher = createDecipheriv('aes-256-gcm', dek, Buffer.from(item.iv, 'base64'));
    cipher.setAAD(Buffer.from(item.aad, 'base64'));
    cipher.setAuthTag(Buffer.from(item.tag, 'base64'));
    return Buffer.concat([cipher.update(Buffer.from(item.ciphertext, 'base64')), cipher.final()]);
  };
  try {
    const commands = JSON.parse(decrypt(envelope));
    assert.equal(commands.fictional, true);
    assert.equal(commands.operation, '3D_PRINT_TOY');
    assert.equal(commands.dimensions.wingspan, 168);
    assert.equal(commands.commands.length, 34);
    assert.deepEqual(commands.commands.map(({ step }) => step), Array.from({ length: 34 }, (_, index) => index + 1));
    assert.ok(commands.commands.every(({ instruction }) => typeof instruction === 'string' && instruction.length > 20));
    assert.match(commands.commands.at(-1).instruction, /no physical robot commands/);
    assert.ok(decrypt(envelope).toString().split('\n').length > 100);
    assert.deepEqual(JSON.parse(Buffer.from(envelope.aad, 'base64')), {
      sequence: 17, issuedAt: envelope.issuedAt, keyId
    });
    for (const field of ['tag', 'ciphertext', 'aad', 'iv']) {
      const bytes = Buffer.from(envelope[field], 'base64');
      bytes[0] ^= 1;
      assert.throws(() => decrypt({ ...envelope, [field]: bytes.toString('base64') }));
    }
    const second = encryptCommands(publicJwk, keyId, 18);
    assert.notEqual(envelope.wrappedKey, second.wrappedKey);
    assert.notEqual(envelope.iv, second.iv);
    assert.ok(!JSON.stringify(envelope).includes('Skylark'));
    assert.ok(!JSON.stringify(envelope).includes('SIMULATION_BEGIN'));
  } finally { dek.fill(0); }
});

test('envelope cache expires in 30 seconds; disabled keys and wrong version URLs fail closed', async () => {
  let time = 0;
  let calls = 0;
  let key = { key: publicJwk, id: keyId, properties: { enabled: true } };
  const service = createEnvelopeService(config, { async getKey() { calls++; return key; } }, () => time);
  const first = await service.get();
  assert.equal(await service.get(), first);
  assert.equal(calls, 1);
  time = 30000;
  assert.equal((await service.get()).sequence, 2);
  service.invalidate();
  key = { ...key, properties: { enabled: false } };
  await assert.rejects(service.get(), fails('worker_key_unavailable'));
  key = { ...key, properties: { enabled: true }, id: keyId.replace('/v1', '') };
  await assert.rejects(service.get(), fails('worker_key_invalid'));
  key = { ...key, id: keyId.replace('example.vault', 'attacker.vault') };
  await assert.rejects(service.get(), fails('worker_key_invalid'));
});

test('in-flight envelope cannot repopulate cache after key invalidation', async () => {
  let resolve;
  const service = createEnvelopeService(config, { getKey: () => new Promise((done) => { resolve = done; }) });
  const result = service.get();
  service.invalidate();
  resolve({ key: publicJwk, id: keyId, properties: { enabled: true } });
  await assert.rejects(result, fails('worker_key_changed'));
});

test('nonce bounds, expiration, unpredictability, and atomic single consumption', () => {
  let now = 100;
  const challenges = new Challenges({ now: () => now, capacity: 2 });
  const a = challenges.issue();
  const b = challenges.issue();
  assert.match(a.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(a.nonce, b.nonce);
  assert.equal(Date.parse(a.expiresAt), 60100);
  assert.throws(() => challenges.issue(), fails('challenge_capacity'));
  challenges.consume(a.nonce);
  assert.throws(() => challenges.consume(a.nonce), fails('nonce_expired_or_replayed'));
  now += 60000;
  assert.throws(() => challenges.consume(b.nonce), fails('nonce_expired_or_replayed'));
  assert.ok(challenges.issue().nonce);
});

test('real attestation and proof signatures accepted once, no assumed MAA audience', async () => {
  const challenges = new Challenges({ now: clock });
  const verifier = createTelemetryVerifier(config, challenges, { jwks: rsa.publicKey, now: clock });
  const { nonce } = challenges.issue();
  const body = {
    attestationToken: await sign({ ...maaClaims(), aud: 'provider-defined-not-entra', exp: current + 3600 }),
    proof: await sign({ nonce, metrics, iat: current, exp: current + 60 }, runtime.privateKey)
  };
  assert.deepEqual(await verifier(body), metrics);
  await assert.rejects(verifier(body), fails('nonce_expired_or_replayed'));
});

test('MAA evidence rejects invalid claims, stale tokens and unbound runtime keys', async (t) => {
  for (const [name, patch, code] of [
    ['issuer', { iss: 'https://wrong.attest.azure.net' }, 'invalid_attestation'],
    ['debug boolean', { 'x-ms-sevsnpvm-is-debuggable': true }, 'attestation_policy_mismatch'],
    ['debug string', { 'x-ms-sevsnpvm-is-debuggable': 'true' }, 'attestation_policy_mismatch'],
    ['missing debug', { 'x-ms-sevsnpvm-is-debuggable': undefined }, 'attestation_policy_mismatch'],
    ['hostdata', { 'x-ms-sevsnpvm-hostdata': 'cd'.repeat(32) }, 'attestation_policy_mismatch'],
    ['compliance', { 'x-ms-compliance-status': 'not-compliant' }, 'attestation_policy_mismatch'],
    ['attestation type', { 'x-ms-attestation-type': 'sgx' }, 'attestation_policy_mismatch'],
    ['runtime missing', { 'x-ms-runtime': {} }, 'invalid_runtime_key'],
    ['private runtime JWK', { 'x-ms-runtime': { keys: [runtime.privateKey.export({ format: 'jwk' })] } }, 'invalid_runtime_key'],
    ['runtime too many', { 'x-ms-runtime': { keys: Array(5).fill(runtimeJwk) } }, 'invalid_runtime_key'],
    ['old issuance', { iat: current - 91, exp: current + 1 }, 'token_not_fresh'],
    ['expired MAA token', { iat: current - 80, exp: current - 1 }, 'token_not_fresh'],
    ['future issuance', { iat: current + 20, exp: current + 50 }, 'token_not_fresh']
  ]) await t.test(name, async () => {
    const challenges = new Challenges({ now: clock });
    const verifier = createTelemetryVerifier(config, challenges, { jwks: rsa.publicKey, now: clock });
    const { nonce } = challenges.issue();
    await assert.rejects(verifier({
      attestationToken: await sign({ ...maaClaims(), ...patch }),
      proof: await sign({ nonce, metrics, iat: current, exp: current + 60 }, runtime.privateKey)
    }), fails(code));
  });
  const challenges = new Challenges({ now: clock });
  const verifier = createTelemetryVerifier(config, challenges, { jwks: rsa.publicKey, now: clock });
  const { nonce } = challenges.issue();
  await assert.rejects(verifier({
    attestationToken: await sign(maaClaims(), runtime.privateKey),
    proof: await sign({ nonce, metrics, iat: current, exp: current + 60 }, runtime.privateKey)
  }), fails('invalid_attestation'));
  await assert.rejects(verifier({
    attestationToken: await sign(maaClaims()),
    proof: await sign({ nonce, metrics, iat: current, exp: current + 60 })
  }), fails('invalid_proof'));
});

test('proof rejects stale timestamps, forged nonces, secret fields and invalid metrics', async (t) => {
  for (const [name, patch, code] of [
    ['old proof', { iat: current - 61, exp: current + 1 }, 'token_not_fresh'],
    ['long proof TTL', { exp: current + 61 }, 'token_not_fresh'],
    ['unknown nonce', { nonce: randomBytes(32).toString('base64url') }, 'nonce_expired_or_replayed'],
    ['invalid nonce', { nonce: 'bad' }, 'invalid_proof_payload'],
    ['commands', { commands: 'not accepted' }, 'invalid_proof_payload'],
    ['extra metrics', { metrics: { ...metrics, secret: 'not accepted' } }, 'invalid_metrics'],
    ['malicious state', { metrics: { ...metrics, state: '<script>oops</script>' } }, 'invalid_metrics']
  ]) await t.test(name, async () => {
    const challenges = new Challenges({ now: clock });
    const verifier = createTelemetryVerifier(config, challenges, { jwks: rsa.publicKey, now: clock });
    const { nonce } = challenges.issue();
    await assert.rejects(verifier({
      attestationToken: await sign(maaClaims()),
      proof: await sign({ nonce, metrics, iat: current, exp: current + 60, ...patch }, runtime.privateKey)
    }), fails(code));
  });
  assert.deepEqual(validateMetrics({ ...metrics, state: 'unavailable' }), { ...metrics, state: 'unavailable' });
  for (const [key, values] of Object.entries({
    latencyMs: [-1, 3600001, NaN, Infinity, '1'],
    uptimeSeconds: [-1, 0.5, 315360001], completedCycles: [-1, 1.5, 1e13], defectRate: [-1, 1.01, '0.1']
  })) for (const value of values) assert.throws(() => validateMetrics({ ...metrics, [key]: value }), fails('invalid_metrics'));
});

test('release gate validates a private RSA key, discards private fields, expires and fails closed', async () => {
  const key = rsa.privateKey.export({ format: 'jwk' });
  validateReleasedKey({ key });
  assert.equal(key.d, undefined);
  assert.throws(() => validateReleasedKey(publicJwk), fails('self_release_invalid'));
  let now = 0;
  let available = true;
  let calls = 0;
  const gate = createGate(config, {
    now: () => now,
    fetchImpl: async (url, options) => {
      calls++;
      assert.equal(url, 'http://127.0.0.1:8080/key/release');
      assert.deepEqual(JSON.parse(options.body), {
        maa_endpoint: 'example.attest.azure.net', akv_endpoint: 'example.vault.azure.net', kid: 'tailspin-control'
      });
      return { ok: available, json: async () => ({ key: rsa.privateKey.export({ format: 'jwk' }) }) };
    }
  });
  assert.equal(gate.ready(), false);
  await Promise.all([gate.require(), gate.require()]);
  assert.equal(calls, 1);
  assert.equal(gate.ready(), true);
  now = 10000;
  assert.equal(gate.ready(), false);
  available = false;
  await assert.rejects(gate.require(), fails('self_release_unavailable'));
  assert.equal(gate.ready(), false);
  available = true;
  await gate.require();
  available = false;
  await assert.rejects(gate.check(), fails('self_release_unavailable'));
  assert.equal(gate.ready(), false);
});

test('release accepts JSON-encoded JWK strings and object responses; malformed strings fail sanitized', async () => {
  const encoded = { key: JSON.stringify(rsa.privateKey.export({ format: 'jwk' })) };
  validateReleasedKey(encoded);
  assert.equal(encoded.key, undefined);
  validateReleasedKey(JSON.stringify(rsa.privateKey.export({ format: 'jwk' })));
  const object = { key: rsa.privateKey.export({ format: 'jwk' }) };
  validateReleasedKey(object);
  assert.equal(object.key.d, undefined);
  for (const key of ['{SECRET-PRIVATE-KEY', '"not a JWK"', 'null', '[]', '{}', 'x'.repeat(32769)]) {
    assert.throws(() => validateReleasedKey({ key }), (error) => {
      assert.equal(error.status, 503);
      assert.equal(error.code, 'self_release_invalid');
      assert.equal(error.message, 'self_release_invalid');
      return true;
    });
  }
  let malformed = false;
  const gate = createGate(config, {
    fetchImpl: async () => ({
      ok: true, json: async () => ({
        key: malformed ? '{SECRET-PRIVATE-KEY' : JSON.stringify(rsa.privateKey.export({ format: 'jwk' }))
      })
    })
  });
  await gate.check();
  assert.equal(gate.ready(), true);
  malformed = true;
  await assert.rejects(gate.check(), fails('self_release_unavailable'));
  assert.equal(gate.ready(), false);
});

test('Confidential approved-template guards and exact ARM request body', async () => {
  assert.doesNotThrow(() => validateWorkerTemplate(approved()));
  for (const body of [null, {}, { sku: 'Standard' }, { ...approved(), properties: {} },
    { ...approved(), properties: { ...approved().properties, sku: 'Standard' } },
    { ...approved(), sku: 'Confidential', properties: { ...approved().properties, sku: 'Standard' } },
    { ...approved(), sku: 'Confidential', properties: { confidentialComputeProperties: { ccePolicy: 'policy' } } },
    { ...approved(), properties: { sku: 'Confidential', confidentialComputeProperties: { ccePolicy: ' ' } } }]) {
    assert.throws(() => validateWorkerTemplate(body), fails('approved_confidential_template_required'));
  }
  let request;
  let scope;
  const raw = JSON.stringify(approved(), null, 2);
  const actions = createActions(config, { async getToken(value) { scope = value; return { token: 'test-token' }; } },
    {}, {}, {
      read: async (file) => { assert.equal(file, 'approved.json'); return raw; },
      fetchImpl: async (url, options) => { request = { url, options }; return { ok: true, status: 201 }; }
    });
  assert.deepEqual(await actions.deploy(), { status: 'accepted', upstreamStatus: 201, operation: 'deploy' });
  assert.equal(scope, 'https://management.azure.com/.default');
  assert.equal(request.options.method, 'PUT');
  assert.equal(request.options.body, raw);
  assert.equal(request.url, `https://management.azure.com${config.workerResourceId}?api-version=2023-05-01`);
  assert.equal(request.options.redirect, 'error');
  await actions.restart();
  assert.equal(request.options.method, 'POST');
  assert.ok(request.url.includes('/restart?api-version='));
  const failing = createActions(config, { async getToken() { return { token: 'secret' }; } }, {}, {}, {
    fetchImpl: async () => ({ ok: false, status: 403, text: () => 'secret Azure response' })
  });
  await assert.rejects(failing.restart(), fails('arm_http_403'));
});

test('revoke disables every enabled version and always invalidates envelopes, including partial failure', async () => {
  const versions = [{ version: 'v1', enabled: true }, { version: 'v2', enabled: false }, { version: 'v3' }];
  const calls = [];
  let invalidations = 0;
  const keyClient = {
    async getKey(name) { assert.equal(name, 'contoso-robot'); return { id: keyId }; },
    async *listPropertiesOfKeyVersions() { yield* versions; },
    async updateKeyProperties(name, version, properties) { calls.push({ name, version, properties }); }
  };
  const actions = createActions(config, {}, keyClient, { invalidate() { invalidations++; } });
  const result = await actions.revoke();
  assert.equal(result.status, 'accepted');
  assert.equal(result.disabledVersions, 2);
  assert.deepEqual(calls.map((x) => x.version), ['v1', 'v3']);
  assert.ok(calls.every((x) => x.name === 'contoso-robot' && x.properties.enabled === false));
  assert.equal(invalidations, 2);
  keyClient.updateKeyProperties = async () => { throw new Error('partial failure'); };
  await assert.rejects(actions.revoke());
  assert.equal(invalidations, 4);
});

test('configuration requires explicit TEST_HTTP, HTTPS origins, separate keys and validated identities', () => {
  const env = {
    NODE_ENV: 'development',
    AZURE_CLIENT_ID: oid, OPERATOR_USERNAME: 'test-operator', OPERATOR_PASSWORD_HASH: 'parent-validated-hash',
    TAILSPIN_URL: config.tailspinUrl, WORKER_URL: config.workerUrl, VAULT_URL: config.vaultUrl,
    MAA_ENDPOINT: config.maaEndpoint, WORKER_POLICY_HASH: config.workerPolicyHash
  };
  assert.equal(loadConfig(env).testHttp, false);
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production' }), /requires TLS_KEY_B64/);
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production', TLS_KEY_B64: 'a' }), /both be provided/);
  assert.throws(() => loadConfig({ ...env, TLS_CERT_B64: 'a' }), /both be provided/);
  assert.equal(loadConfig({
    ...env, NODE_ENV: 'production', TLS_KEY_B64: 'key-validated-at-startup', TLS_CERT_B64: 'cert-validated-at-startup'
  }).development, false);
  assert.throws(() => loadConfig({ ...env, TAILSPIN_URL: 'http://localhost:8443' }));
  assert.equal(loadConfig({ ...env, TEST_HTTP: '1', TAILSPIN_URL: 'http://localhost:8443' }).testHttp, true);
  assert.throws(() => loadConfig({ ...env, TEST_HTTP: '1', TAILSPIN_URL: 'http://remote.example' }));
  assert.throws(() => loadConfig({ ...env, SELF_KEY_NAME: 'contoso-robot' }));
  assert.throws(() => loadConfig({ ...env, WORKER_POLICY_HASH: '' }));
  assert.throws(() => loadConfig({ ...env, OPERATOR_USERNAME: '' }), /Missing OPERATOR_USERNAME/);
  assert.throws(() => loadConfig({ ...env, OPERATOR_PASSWORD_HASH: '' }), /Missing OPERATOR_PASSWORD_HASH/);
  assert.equal(loadConfig(env).operatorUsername, 'test-operator');
  assert.equal(loadConfig(env).operatorPasswordHash, 'parent-validated-hash');
  assert.equal('tenantId' in loadConfig(env), false);
  assert.throws(() => loadConfig({ ...env, AZURE_CLIENT_ID: 'not-an-id' }), /Invalid AZURE_CLIENT_ID/);
  assert.throws(() => loadConfig({ ...env, MAA_ENDPOINT: `${config.maaEndpoint}/other-path` }));
  assert.throws(() => loadConfig({ ...env, WORKER_RESOURCE_ID: '/evil?query=x' }));
});
