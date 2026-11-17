import { createPrivateKey, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, importJWK, jwtVerify } from 'jose';

export class AppError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export class Challenges {
  constructor({ now = Date.now, capacity = 2000 } = {}) {
    this.now = now;
    this.capacity = capacity;
    this.items = new Map();
  }
  issue() {
    const now = this.now();
    for (const [nonce, expires] of this.items) if (expires <= now) this.items.delete(nonce);
    if (this.items.size >= this.capacity) throw new AppError(429, 'challenge_capacity');
    const nonce = randomBytes(32).toString('base64url');
    const expires = now + 60000;
    this.items.set(nonce, expires);
    return { nonce, expiresAt: new Date(expires).toISOString() };
  }
  consume(nonce) {
    const expires = this.items.get(nonce);
    this.items.delete(nonce);
    if (!expires || expires <= this.now()) throw new AppError(401, 'nonce_expired_or_replayed');
  }
}

function fresh(payload, now, maxAge, maxLifetime = maxAge) {
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp) ||
      payload.iat > now + 5 || now - payload.iat > maxAge ||
      payload.exp <= now || payload.exp <= payload.iat || payload.exp - payload.iat > maxLifetime) {
    throw new AppError(401, 'token_not_fresh');
  }
}

export function validateMetrics(metrics) {
  if (!metrics || typeof metrics !== 'object' || Array.isArray(metrics) ||
      Object.keys(metrics).sort().join(',') !== 'completedCycles,defectRate,latencyMs,state,uptimeSeconds' ||
      !['protected', 'unavailable'].includes(metrics.state)) throw new AppError(400, 'invalid_metrics');
  const limits = { latencyMs: 3600000, uptimeSeconds: 315360000, completedCycles: 1e12, defectRate: 1 };
  for (const [name, max] of Object.entries(limits)) {
    if (typeof metrics[name] !== 'number' || !Number.isFinite(metrics[name]) ||
        metrics[name] < 0 || metrics[name] > max ||
        (['uptimeSeconds', 'completedCycles'].includes(name) && !Number.isSafeInteger(metrics[name]))) {
      throw new AppError(400, 'invalid_metrics');
    }
  }
  return Object.fromEntries(['state', ...Object.keys(limits)].map((key) => [key, metrics[key]]));
}

export function publicRuntimeKey(key) {
  if (!key || key.kty !== 'RSA' || key.e !== 'AQAB' || typeof key.n !== 'string' ||
      !/^[A-Za-z0-9_-]+$/.test(key.n) || key.n.length > 1366 ||
      ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some((name) => name in key)) return false;
  const modulus = Buffer.from(key.n, 'base64url');
  return modulus.length >= 256 && modulus.length <= 1024 && modulus[0] >= 128;
}

export function createTelemetryVerifier(config, challenges, { verify = jwtVerify, jwks, now = Date.now } = {}) {
  const keyset = jwks ?? createRemoteJWKSet(new URL(`${config.maaEndpoint}/certs`), { timeoutDuration: 5000 });
  return async (body) => {
    if (!body || Object.keys(body).sort().join(',') !== 'attestationToken,proof' ||
        typeof body.attestationToken !== 'string' || body.attestationToken.length > 48000 ||
        typeof body.proof !== 'string' || body.proof.length > 16000) throw new AppError(400, 'invalid_telemetry');
    let attestation;
    try {
      ({ payload: attestation } = await verify(body.attestationToken, keyset, {
        issuer: config.maaEndpoint,
        algorithms: ['RS256'],
        requiredClaims: ['exp', 'iat'],
        currentDate: new Date(now()),
        clockTolerance: 5
      }));
    } catch { throw new AppError(401, 'invalid_attestation'); }
    // MAA controls its signed expiry. Fresh issuance, not shortening its service TTL,
    // is what binds this proof to recent evidence.
    fresh(attestation, Math.floor(now() / 1000), 90, Infinity);
    if (attestation['x-ms-compliance-status'] !== 'azure-compliant-uvm' ||
        ![false, 'false'].includes(attestation['x-ms-sevsnpvm-is-debuggable']) ||
        attestation['x-ms-sevsnpvm-hostdata'] !== config.workerPolicyHash ||
        attestation['x-ms-attestation-type'] !== 'sevsnpvm') throw new AppError(401, 'attestation_policy_mismatch');
    const keys = attestation['x-ms-runtime']?.keys;
    if (!Array.isArray(keys) || !keys.length || keys.length > 4 || !keys.every(publicRuntimeKey)) {
      throw new AppError(401, 'invalid_runtime_key');
    }
    let proof;
    for (const key of keys) {
      try {
        const verified = await jwtVerify(body.proof, await importJWK(key, 'RS256'), {
          algorithms: ['RS256'], requiredClaims: ['iat', 'exp', 'nonce', 'metrics'],
          currentDate: new Date(now()), clockTolerance: 5
        });
        proof = verified.payload;
        break;
      } catch { /* Only a key bound into this verified MAA token can prove possession. */ }
    }
    if (!proof) throw new AppError(401, 'invalid_proof');
    fresh(proof, Math.floor(now() / 1000), 60);
    if (typeof proof.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(proof.nonce) ||
        Object.keys(proof).some((key) => !['nonce', 'metrics', 'iat', 'exp'].includes(key))) {
      throw new AppError(400, 'invalid_proof_payload');
    }
    const metrics = validateMetrics(proof.metrics);
    challenges.consume(proof.nonce);
    return metrics;
  };
}

export function validateReleasedKey(body) {
  let jwk = body?.key ?? body;
  try {
    if (typeof jwk === 'string') {
      if (jwk.length > 32768) throw new Error();
      jwk = JSON.parse(jwk);
    }
    if (!jwk || jwk.kty !== 'RSA' || !['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'].every(
      (name) => typeof jwk[name] === 'string' && /^[A-Za-z0-9_-]+$/.test(jwk[name])
    )) throw new Error();
    const key = createPrivateKey({ key: jwk, format: 'jwk' });
    if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 2048) throw new Error();
  } catch { throw new AppError(503, 'self_release_invalid'); }
  finally {
    if (jwk && typeof jwk === 'object') {
      for (const name of ['d', 'p', 'q', 'dp', 'dq', 'qi']) delete jwk[name];
    }
    if (body && typeof body === 'object' && typeof body.key === 'string') delete body.key;
  }
}

export function createGate(config, { fetchImpl = fetch, now = Date.now, onChange = () => {} } = {}) {
  let lastSuccess = -Infinity;
  let pending;
  let previous = false;
  const ready = () => now() - lastSuccess < 10000;
  const check = () => {
    if (pending) return pending;
    pending = (async () => {
      try {
        const response = await fetchImpl('http://127.0.0.1:8080/key/release', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            maa_endpoint: new URL(config.maaEndpoint).hostname,
            akv_endpoint: new URL(config.vaultUrl).hostname,
            kid: config.selfKeyName
          }), signal: AbortSignal.timeout(8000), redirect: 'error'
        });
        if (!response.ok) throw new Error();
        validateReleasedKey(await response.json());
        lastSuccess = now();
        if (!previous) onChange(true);
        previous = true;
      } catch {
        lastSuccess = -Infinity;
        if (previous) onChange(false);
        previous = false;
        throw new AppError(503, 'self_release_unavailable');
      } finally { pending = undefined; }
    })();
    return pending;
  };
  return {
    ready, check,
    async require() {
      if (!ready()) await check();
      if (!ready()) throw new AppError(503, 'self_release_unavailable');
    }
  };
}
