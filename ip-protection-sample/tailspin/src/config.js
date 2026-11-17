import { AppError } from './security.js';

const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function loadConfig(env = process.env) {
  const required = (name) => {
    if (!env[name]?.trim()) throw new Error(`Missing ${name}`);
    return env[name].trim();
  };
  const identifier = (name) => {
    const value = required(name);
    if (!guid.test(value)) throw new Error(`Invalid ${name}`);
    return value;
  };
  const url = (name, allowLocal = false) => {
    const parsed = new URL(required(name));
    const localTest = allowLocal && env.TEST_HTTP === '1' &&
      parsed.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(parsed.hostname);
    if ((!localTest && parsed.protocol !== 'https:') || parsed.username ||
        parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') {
      throw new Error(`Invalid ${name}: expected HTTPS origin`);
    }
    return parsed.origin;
  };
  const workerPolicyHash = required('WORKER_POLICY_HASH').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(workerPolicyHash)) throw new Error('Invalid WORKER_POLICY_HASH');
  const keyName = (name, fallback) => {
    const value = env[name] || fallback;
    if (!/^[a-z0-9-]{1,127}$/i.test(value)) throw new Error(`Invalid ${name}`);
    return value;
  };
  const selfKeyName = keyName('SELF_KEY_NAME', 'tailspin-control');
  const workerKeyName = keyName('WORKER_KEY_NAME', 'contoso-robot');
  if (selfKeyName === workerKeyName) throw new Error('Self and worker keys must be separate');
  const workerResourceId = env.WORKER_RESOURCE_ID?.trim();
  if (workerResourceId && !/^\/subscriptions\/[a-f0-9-]{36}\/resourceGroups\/[^/?#]+\/providers\/Microsoft\.ContainerInstance\/containerGroups\/[a-z0-9-]+$/i.test(workerResourceId)) {
    throw new Error('Invalid WORKER_RESOURCE_ID');
  }
  const workerApiVersion = env.WORKER_API_VERSION || '2023-05-01';
  if (!/^\d{4}-\d{2}-\d{2}(?:-preview)?$/.test(workerApiVersion)) throw new Error('Invalid WORKER_API_VERSION');
  const tlsKeyB64 = env.TLS_KEY_B64;
  const tlsCertB64 = env.TLS_CERT_B64;
  if (!!tlsKeyB64 !== !!tlsCertB64) throw new Error('TLS_KEY_B64 and TLS_CERT_B64 must both be provided');
  const development = env.NODE_ENV === 'development';
  if (env.TEST_HTTP !== '1' && !development && !tlsKeyB64) {
    throw new Error('Production HTTPS requires TLS_KEY_B64 and TLS_CERT_B64');
  }
  return {
    clientId: identifier('AZURE_CLIENT_ID'),
    operatorUsername: required('OPERATOR_USERNAME'),
    operatorPasswordHash: required('OPERATOR_PASSWORD_HASH'),
    tailspinUrl: url('TAILSPIN_URL', true),
    workerUrl: url('WORKER_URL', true),
    vaultUrl: url('VAULT_URL'),
    maaEndpoint: url('MAA_ENDPOINT'),
    workerPolicyHash,
    selfKeyName,
    workerKeyName,
    workerResourceId,
    workerApiVersion,
    workerTemplatePath: env.WORKER_TEMPLATE_PATH || '/app/deploy/worker.json',
    tlsKeyB64,
    tlsCertB64,
    development,
    testHttp: env.TEST_HTTP === '1'
  };
}

export function requireResource(config) {
  if (!config.workerResourceId) throw new AppError(503, 'worker_resource_not_configured');
}
