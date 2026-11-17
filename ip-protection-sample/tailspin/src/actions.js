import { readFile } from 'node:fs/promises';
import { AppError } from './security.js';
import { requireResource } from './config.js';

export function validateWorkerTemplate(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) ||
      body.properties?.sku !== 'Confidential' ||
      typeof body.properties?.confidentialComputeProperties?.ccePolicy !== 'string' ||
      !body.properties.confidentialComputeProperties.ccePolicy.trim()) {
    throw new AppError(400, 'approved_confidential_template_required');
  }
  return body;
}

export function createActions(config, credential, keyClient, envelopes, {
  fetchImpl = fetch, read = readFile
} = {}) {
  const arm = async (method, suffix, body) => {
    requireResource(config);
    const token = await credential.getToken('https://management.azure.com/.default');
    if (!token?.token) throw new AppError(503, 'arm_identity_unavailable');
    const resource = `https://management.azure.com${config.workerResourceId}${suffix}?api-version=${config.workerApiVersion}`;
    const response = await fetchImpl(resource, {
      method, headers: { authorization: `Bearer ${token.token}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body }),
      signal: AbortSignal.timeout(15000), redirect: 'error'
    });
    if (!response.ok) throw new AppError(response.status >= 400 && response.status < 600 ? response.status : 502, `arm_http_${response.status}`);
    // Azure's operation URL may carry service-specific data; don't expose it in the browser.
    return { status: 'accepted', upstreamStatus: response.status, operation: suffix ? 'restart' : 'deploy' };
  };
  return {
    async deploy() {
      let raw;
      try { raw = await read(config.workerTemplatePath, 'utf8'); }
      catch { throw new AppError(503, 'approved_template_unavailable'); }
      let body;
      try { body = JSON.parse(raw); }
      catch { throw new AppError(400, 'approved_template_invalid_json'); }
      validateWorkerTemplate(body);
      return arm('PUT', '', raw);
    },
    restart() { return arm('POST', '/restart'); },
    async revoke() {
      envelopes.invalidate();
      let disabledVersions = 0;
      try {
        // Confirm this key exists, but do not assume its latest version is the only one in use.
        await keyClient.getKey(config.workerKeyName);
        for await (const version of keyClient.listPropertiesOfKeyVersions(config.workerKeyName)) {
          if (version.enabled !== false) {
            if (!version.version) throw new AppError(502, 'worker_key_version_missing');
            await keyClient.updateKeyProperties(config.workerKeyName, version.version, { enabled: false });
            disabledVersions++;
          }
        }
      } finally { envelopes.invalidate(); }
      return {
        status: 'accepted', operation: 'revoke', disabledVersions,
        detail: 'Existing released keys cannot be recalled. Observe the worker heartbeat; restart to discard worker memory.'
      };
    }
  };
}
