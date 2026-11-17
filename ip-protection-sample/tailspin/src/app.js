import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError } from './security.js';
import { installDemoUi } from '../../ui/server.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

export function createApp(config, {
  operatorAuth, authenticate, gate, envelopes, challenges, verifyTelemetry, actions, keyClient,
  now = Date.now, stdout = () => {}
}) {
  const app = express();
  const records = [];
  const securityEvents = [];
  const evidenceFailures = new Set([
    'invalid_attestation', 'attestation_policy_mismatch', 'invalid_runtime_key',
    'invalid_proof', 'token_not_fresh', 'nonce_expired_or_replayed', 'invalid_metrics',
    'invalid_telemetry', 'invalid_proof_payload', 'invalid_json', 'payload_too_large',
    'evidence_verification_unavailable'
  ]);
  let lastSeen = null;
  let keyStatus = { status: 'unknown', checkedAt: null };
  let nextKeyCheck = 0;
  let keyCheck;
  const append = (list, value) => { list.push(value); if (list.length > 500) list.shift(); };
  const security = (event, outcome, reason) => {
    const record = {
      at: new Date(now()).toISOString(), event, outcome,
      ...(evidenceFailures.has(reason) ? { reason } : {})
    };
    append(securityEvents, record);
    stdout(record);
  };
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use((req, res, next) => {
    res.set({
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    });
    if (!config.testHttp) res.set('Strict-Transport-Security', 'max-age=31536000');
    next();
  });
  app.use(express.json({ limit: '72kb', strict: true }));
  if (operatorAuth) operatorAuth.install(app);
  else if (typeof authenticate !== 'function') throw new Error('Operator authentication is required');
  const jsonOnly = (req, _res, next) => {
    if (!req.is('application/json')) return next(new AppError(415, 'json_required'));
    next();
  };
  const operator = operatorAuth ? operatorAuth.requireOperator : async (req, _res, next) => {
    try { req.operator = await authenticate(req.get('authorization')); next(); }
    catch (error) { security('operator_auth', 'rejected'); next(error); }
  };
  const requireGate = async (_req, _res, next) => {
    try { await gate.require(); next(); }
    catch (error) { security('self_key_release', 'unavailable'); next(error); }
  };
  const sameOrigin = (req, _res, next) => {
    if (req.get('origin') !== config.tailspinUrl) {
      security('management_origin', 'rejected');
      return next(new AppError(403, 'origin_forbidden'));
    }
    next();
  };

  app.get('/api/config', (_req, res) => res.json({
    tailspinUrl: config.tailspinUrl, workerUrl: config.workerUrl
  }));
  app.get('/api/health', (_req, res) => {
    const ready = gate.ready();
    res.status(ready ? 200 : 503).json({ ready });
  });
  app.get('/api/envelope', requireGate, async (_req, res) => res.json(await envelopes.get()));
  app.get('/api/challenge', requireGate, (_req, res) => res.json(challenges.issue()));
  app.post('/api/telemetry', jsonOnly, requireGate, async (req, res) => {
    try {
      const metrics = await verifyTelemetry(req.body);
      const at = new Date(now()).toISOString();
      lastSeen = at;
      append(records, { at, ...metrics });
      security('worker_attestation_and_proof', 'verified');
      res.status(202).json({ status: 'accepted' });
    } catch (error) {
      security('worker_attestation_and_proof', 'rejected',
        error instanceof AppError && evidenceFailures.has(error.code) ? error.code : 'evidence_verification_unavailable');
      throw error;
    }
  });
  app.get('/api/dashboard', operator, async (_req, res) => {
    if (keyClient && now() >= nextKeyCheck && !keyCheck) {
      keyCheck = (async () => {
        try {
          const key = await keyClient.getKey(config.workerKeyName);
          keyStatus = {
            status: key.properties.enabled === false ? 'disabled' : 'enabled',
            checkedAt: new Date(now()).toISOString()
          };
        } catch { keyStatus = { status: 'unavailable', checkedAt: new Date(now()).toISOString() }; }
        finally { nextKeyCheck = now() + 30000; keyCheck = undefined; }
      })();
    }
    if (keyCheck) await keyCheck;
    const window = records.filter((r) => now() - Date.parse(r.at) <= 3600000);
    const protectedSamples = window.filter((r) => r.state === 'protected').length;
    const ageMs = lastSeen === null ? null : Math.max(0, now() - Date.parse(lastSeen));
    res.json({
      metricProvenance: {
        state: 'worker-reported',
        latencyMs: 'worker-reported-measured',
        uptimeSeconds: 'worker-reported-process',
        completedCycles: 'worker-reported-count',
        defectRate: 'synthetic'
      },
      metricAssurance: 'Signature-verified worker reports; measurements and physical manufacturing outcomes are not independently proven.',
      storage: 'In-memory only; not durable. Samples are retained until process restart, maximum 500.',
      selfReleaseReady: gate.ready(), workerKey: keyStatus,
      heartbeat: { lastSeen, ageMs, status: ageMs === null ? 'unknown' : ageMs <= 30000 ? 'receiving' : 'stale' },
      availability: {
        status: window.length ? 'measured' : 'unknown',
        protectedSamplePercent: window.length ? Number((protectedSamples * 100 / window.length).toFixed(2)) : null,
        sampleCount: window.length,
        windowSeconds: 3600,
        definition: 'Protected / attested samples received in the last hour; not a wall-clock availability SLA.'
      },
      records: [...records].reverse(), securityEvents: [...securityEvents].reverse()
    });
  });
  for (const action of ['deploy', 'restart', 'revoke']) {
    let active = false;
    app.post(`/api/actions/${action}`, operator, sameOrigin, jsonOnly, requireGate, async (req, res) => {
      if (!req.body || Array.isArray(req.body) || Object.keys(req.body).length) throw new AppError(400, 'empty_action_body_required');
      if (active) throw new AppError(409, 'action_in_progress');
      active = true;
      security(`management_${action}`, 'requested');
      try {
        const result = await actions[action]();
        if (action === 'revoke') nextKeyCheck = 0;
        security(`management_${action}`, 'accepted');
        res.status(202).json(result);
      } catch (error) {
        security(`management_${action}`, 'failed');
        throw error;
      } finally { active = false; }
    });
  }
  installDemoUi(app);
  app.use(express.static(path.join(root, 'public'), { etag: false, maxAge: 0 }));
  app.use((_req, _res, next) => next(new AppError(404, 'not_found')));
  app.use((error, req, res, _next) => {
    const status = error instanceof AppError ? error.status : error.type === 'entity.too.large' ? 413 :
      error.type === 'entity.parse.failed' ? 400 : 503;
    const code = error instanceof AppError ? error.code : status === 413 ? 'payload_too_large' :
      status === 400 ? 'invalid_json' : 'dependency_unavailable';
    if (req.path === '/api/telemetry' && ['invalid_json', 'payload_too_large'].includes(code)) {
      security('telemetry_input', 'rejected', code);
    }
    res.status(status).json({ error: code });
  });
  return { app, security };
}
