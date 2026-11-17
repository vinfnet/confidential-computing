import { decryptEnvelope } from './transport.mjs';

const required = ['TLS_ENVELOPE', 'TLS_KEY_NAME', 'MAA_ENDPOINT', 'VAULT_URL'];
for (const name of required) if (!process.env[name]) throw new Error(`Missing ${name}`);
const envelope = JSON.parse(process.env.TLS_ENVELOPE);
let released;
for (let attempt = 0; attempt < 12; attempt++) {
  try {
    const response = await fetch('http://127.0.0.1:8080/key/release', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        maa_endpoint: new URL(process.env.MAA_ENDPOINT).hostname,
        akv_endpoint: new URL(process.env.VAULT_URL).hostname,
        kid: envelope.keyId.split('/').slice(-2).join('/')
      }), signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error(`Transport SKR returned HTTP ${response.status}`);
    released = await response.json();
    break;
  } catch (error) {
    console.error(JSON.stringify({ event: 'transport-bootstrap-unavailable', attempt: attempt + 1, reason: error.message }));
    if (attempt === 11) throw error;
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
}
const jwk = typeof released.key === 'string' ? JSON.parse(released.key) : released.key;
const plaintext = decryptEnvelope(envelope, jwk, process.env.VAULT_URL, process.env.TLS_KEY_NAME);
try { process.env.TLS_KEY_B64 = plaintext.toString('base64'); }
finally {
  plaintext.fill(0);
  for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) delete jwk[field];
}
const application = await import(process.env.APPLICATION_ENTRYPOINT || './server.mjs');
if (typeof application.start === 'function') await application.start();
