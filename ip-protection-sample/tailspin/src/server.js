import https from 'node:https';
import http from 'node:http';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { generate } from 'selfsigned';
import { isIP } from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { ManagedIdentityCredential } from '@azure/identity';
import { KeyClient } from '@azure/keyvault-keys';
import { loadConfig } from './config.js';
import { Challenges, createGate, createTelemetryVerifier } from './security.js';
import { createEnvelopeService } from './envelope.js';
import { createActions } from './actions.js';
import { createApp } from './app.js';

export async function ephemeralTls(config) {
  const hostname = new URL(config.tailspinUrl).hostname;
  if (!/^[a-z0-9.-]+$/i.test(hostname)) throw new Error('Invalid TLS hostname');
  const certificate = await generate([{ name: 'commonName', value: 'Tailspin Demo' }], {
    keySize: 3072,
    algorithm: 'sha256',
    notAfterDate: new Date(Date.now() + 86400000),
    extensions: [
      { name: 'basicConstraints', cA: false, critical: true },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames: [
        { type: 2, value: hostname }, { type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }
      ] }
    ]
  });
  return {
    key: Buffer.from(certificate.private), cert: Buffer.from(certificate.cert), minVersion: 'TLSv1.2'
  };
}

export async function tlsOptions(config) {
  if (!!config.tlsKeyB64 !== !!config.tlsCertB64) throw new Error('Both TLS values are required');
  if (!config.tlsKeyB64) {
    if (!config.development) throw new Error('Production TLS material is required');
    return ephemeralTls(config);
  }
  const decode = (value) => {
    if (typeof value !== 'string' || value.length > 100000 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      throw new Error('Invalid TLS encoding');
    }
    return Buffer.from(value, 'base64');
  };
  const key = decode(config.tlsKeyB64);
  try {
    const cert = decode(config.tlsCertB64);
    const certificate = new X509Certificate(cert);
    const privateKey = createPrivateKey(key);
    const hostname = new URL(config.tailspinUrl).hostname;
    const validHost = isIP(hostname) ? certificate.checkIP(hostname) : certificate.checkHost(hostname);
    if (!certificate.checkPrivateKey(privateKey) || !validHost ||
        Date.parse(certificate.validFrom) > Date.now() ||
        Date.parse(certificate.validTo) <= Date.now()) throw new Error('Invalid TLS certificate');
    return { key, cert, minVersion: 'TLSv1.2' };
  } catch {
    key.fill(0);
    throw new Error('Invalid TLS material');
  }
}

export async function start(config = loadConfig()) {
  const { createOperatorAuth } = await import('../../auth/operator.mjs');
  const tls = config.testHttp ? null : await tlsOptions(config);
  const credential = new ManagedIdentityCredential({ clientId: config.clientId });
  const keyClient = new KeyClient(config.vaultUrl, credential, {
    retryOptions: { maxRetries: 1, retryDelayInMs: 300, maxRetryDelayInMs: 1000 }
  });
  const envelopes = createEnvelopeService(config, keyClient);
  const challenges = new Challenges();
  let report = () => {};
  const operatorAuth = createOperatorAuth({
    username: config.operatorUsername,
    passwordHash: config.operatorPasswordHash,
    origin: config.tailspinUrl,
    onEvent: ({ event, outcome }) => report(event, outcome)
  });
  const gate = createGate(config, {
    onChange: (ready) => report('self_key_release', ready ? 'verified' : 'unavailable')
  });
  const { app, security } = createApp(config, {
    operatorAuth, gate, envelopes, challenges,
    verifyTelemetry: createTelemetryVerifier(config, challenges),
    actions: createActions(config, credential, keyClient, envelopes), keyClient
  });
  report = security;
  // Serve the public UI and minimal readiness while release is pending or unavailable.
  void gate.check().catch(() => security('self_key_release', 'unavailable'));
  const timer = setInterval(() => gate.check().catch(() => {}), 10000);
  timer.unref();
  let server;
  try {
    server = config.testHttp ? http.createServer(app) : https.createServer(tls, app);
    server.requestTimeout = 20000;
    server.headersTimeout = 15000;
    server.keepAliveTimeout = 5000;
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(8443, config.testHttp ? '127.0.0.1' : '0.0.0.0', resolve);
    });
  } catch (error) { clearInterval(timer); throw error; }
  server.once('close', () => clearInterval(timer));
  security('https_listener', config.testHttp ? 'localhost_test_http' : 'started');
  const close = () => { clearInterval(timer); server.close(); };
  process.once('SIGTERM', close);
  process.once('SIGINT', close);
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  start().catch(() => {
    // Dependency bodies, release keys, tokens and command plaintext must never reach stdout.
    process.stderr.write('Tailspin startup failed; check required configuration and TLS material.\n');
    process.exitCode = 1;
  });
}
