import { execFileSync } from 'node:child_process';
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { randomBytes, createHash, createCipheriv, createPublicKey, publicEncrypt, constants } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyPolicy } from './policy.mjs';
import { hashPassword } from '../auth/operator.mjs';
import { deploymentSummary } from './deployment-summary.mjs';
import { assertDeploymentOwner, resourcePrefix } from './deployment-settings.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const generated = path.join(root, '.generated');
const az = process.env.AZ_PATH || (process.platform === 'win32' ?
  'C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd' : 'az');
const api = '2026-07-01';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function run(file, args, options = {}) {
  const command = process.platform === 'win32' && file.endsWith('.cmd') ?
    [process.env.ComSpec, ['/d', '/s', '/c', `"${[file, ...args].map((a) => `"${a.replaceAll('"', '\\"')}"`).join(' ')}"`]] :
    [file, args];
  return execFileSync(command[0], command[1], { cwd: root, encoding: 'utf8',
    windowsVerbatimArguments: process.platform === 'win32' && file.endsWith('.cmd'),
    maxBuffer: 20 * 1024 * 1024, ...options });
}
function cli(args) { return run(az, [...args, '--only-show-errors']); }
function token(resource) {
  return JSON.parse(cli(['account', 'get-access-token', '--resource', resource, '-o', 'json'])).accessToken;
}
const tokens = new Map();
async function request(method, url, body, resource = 'https://management.azure.com/', missingOk = false) {
  if (!tokens.has(resource)) tokens.set(resource, token(resource));
  const response = await fetch(url, {
    method, headers: { Authorization: `Bearer ${tokens.get(resource)}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(90000)
  });
  if (missingOk && response.status === 404) return null;
  const text = await response.text();
  if (!response.ok) throw new Error(`${method} ${new URL(url).pathname}: HTTP ${response.status}: ${text.slice(0, 1800)}`);
  return text ? JSON.parse(text) : {};
}
const arm = (method, id, version, body, missingOk = false) =>
  request(method, `https://management.azure.com${id}?api-version=${version}`, body, undefined, missingOk);
async function save(name, value) {
  await writeFile(path.join(generated, name), typeof value === 'string' ? value : JSON.stringify(value, null, 2));
}
async function waitResource(id, version, max = 120) {
  for (let i = 0; i < max; i++) {
    const result = await arm('GET', id, version);
    const status = result.properties?.provisioningState;
    if (status === 'Failed' || status === 'Canceled') throw new Error(`${id} provisioning ${status}: ${JSON.stringify(result.properties?.instanceView || {})}`);
    if (status === 'Succeeded') return result;
    await sleep(10000);
  }
  throw new Error(`Timed out waiting for ${id}; resources retained for diagnosis`);
}
async function role(scope, principalId, roleId) {
  const name = createHash('sha256').update(`${scope}:${principalId}:${roleId}`).digest('hex').slice(0, 32);
  const guid = `${name.slice(0, 8)}-${name.slice(8, 12)}-${name.slice(12, 16)}-${name.slice(16, 20)}-${name.slice(20)}`;
  await arm('PUT', `${scope}/providers/Microsoft.Authorization/roleAssignments/${guid}`, '2022-04-01', {
    properties: { principalId, principalType: principalId === config.operatorOid ? 'User' : 'ServicePrincipal',
      roleDefinitionId: `/subscriptions/${config.subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${roleId}` }
  });
}
let config;
async function init() {
  await mkdir(generated, { recursive: true });
  const user = JSON.parse(cli(['ad', 'signed-in-user', 'show', '-o', 'json']));
  try { config = JSON.parse(await readFile(path.join(generated, 'deployment.json'), 'utf8')); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const account = JSON.parse(cli(['account', 'show', '-o', 'json']));
    const suffix = randomBytes(4).toString('hex');
    const prefix = resourcePrefix(process.env.RESOURCE_PREFIX);
    config = { subscriptionId: account.id, tenantId: account.tenantId, upn: user.userPrincipalName,
      operatorOid: user.id, location: process.env.AZURE_LOCATION || 'westeurope', suffix,
      tailspinGroup: `${prefix}tailspintoys-ip-${suffix}`, contosoGroup: `${prefix}contoso-ip-${suffix}`,
      registry: `${prefix}tailspin${suffix}`, vault: `${prefix}tailspin${suffix}`,
      attestation: `${prefix}tailspin${suffix}`, workerName: `contoso-robot-${suffix}`,
      controlName: `tailspin-control-${suffix}` };
    await save('deployment.json', config);
  }
  assertDeploymentOwner(config.upn, user.userPrincipalName, process.env.ALLOW_DIFFERENT_OWNER === '1');
  console.log(`Demo ${config.suffix}: ${config.subscriptionId}, ${config.upn}, ${config.location}`);
  await operatorCredentials();
}
const rgId = (name) => `/subscriptions/${config.subscriptionId}/resourceGroups/${name}`;
const tailId = (type, name) => `${rgId(config.tailspinGroup)}/providers/${type}/${name}`;
const tags = (company) => ({ owner: config.upn, scenario: 'manufacturing-ip-protection', demoId: config.suffix, company, managedBy: 'Tailspin Toys' });

async function operatorCredentials() {
  const file = path.join(generated, 'operator-credentials.json');
  let credentials;
  try { credentials = JSON.parse(await readFile(file, 'utf8')); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    if (config.operatorPasswordHash) throw new Error('Operator credential file is missing; refusing to silently replace deployed credentials');
    const password = randomBytes(32).toString('base64url');
    credentials = { username: 'tailspin.operator', password, passwordHash: await hashPassword(password) };
    await writeFile(file, '', { flag: 'wx', mode: 0o600 });
    if (process.platform === 'win32') {
      const sid = run('whoami', ['/user', '/fo', 'csv', '/nh']).match(/S-\d(?:-\d+)+/)?.[0];
      if (!sid) throw new Error('Cannot resolve Windows identity for private credential-file ACL');
      run('icacls', [file, '/inheritance:r', '/grant:r', `*${sid}:(F)`]);
    }
    await writeFile(file, JSON.stringify(credentials, null, 2), { mode: 0o600 });
  }
  if (!credentials.username || !credentials.password || !/^scrypt\$[a-f0-9]{32}\$[a-f0-9]{128}$/.test(credentials.passwordHash) ||
      (config.operatorPasswordHash && config.operatorPasswordHash !== credentials.passwordHash)) {
    throw new Error('Operator credential configuration is inconsistent; restore the private credential file');
  }
  config.operatorUsername = credentials.username;
  config.operatorPasswordHash = credentials.passwordHash;
  config.authMode = 'password';
  await save('deployment.json', config);
  console.log('Operator credentials retained privately in .generated/operator-credentials.json (not printed or deployed)');
}
async function foundation() {
  config.vaultUrl = `https://${config.vault}.vault.azure.net`;
  config.workerResourceId = `${rgId(config.contosoGroup)}/providers/Microsoft.ContainerInstance/containerGroups/${config.workerName}`;
  config.controlResourceId = tailId('Microsoft.ContainerInstance/containerGroups', config.controlName);
  config.workerUrl = `https://${config.workerName}.${config.location}.azurecontainer.io:8443`;
  config.tailspinUrl = `https://${config.controlName}.${config.location}.azurecontainer.io:8443`;
  await save('deployment.json', config);
  for (const [name, company] of [[config.tailspinGroup, 'Tailspin Toys'], [config.contosoGroup, 'Contoso']]) {
    const existing = await arm('GET', rgId(name), '2024-03-01', undefined, true);
    if (existing && existing.tags?.demoId !== config.suffix) throw new Error(`Refusing to touch existing group ${name}`);
    await arm('PUT', rgId(name), '2024-03-01', { location: config.location, tags: tags(company) });
  }
  for (const name of ['tailspin-control', 'tailspin-robot']) {
    const mi = await arm('PUT', tailId('Microsoft.ManagedIdentity/userAssignedIdentities', name), '2024-11-30',
      { location: config.location, tags: tags('Tailspin Toys') });
    config[name === 'tailspin-control' ? 'controlIdentity' : 'workerIdentity'] = { id: mi.id, ...mi.properties };
  }
  const vaultId = tailId('Microsoft.KeyVault/vaults', config.vault);
  await arm('PUT', vaultId, '2026-05-15', {
    location: config.location, tags: tags('Tailspin Toys'),
    properties: { tenantId: config.tenantId, sku: { family: 'A', name: 'premium' },
      enableRbacAuthorization: true, enableSoftDelete: true, enablePurgeProtection: true,
      softDeleteRetentionInDays: 7, publicNetworkAccess: 'Enabled',
      networkAcls: { bypass: 'AzureServices', defaultAction: 'Allow' } }
  });
  await waitResource(vaultId, '2026-05-15');
  // The operator owns only this new vault; no subscription-wide data-plane grant.
  await role(vaultId, config.operatorOid, '00482a5a-887f-4fb3-b363-3b7fe8e74483');
  await role(vaultId, config.controlIdentity.principalId, '00482a5a-887f-4fb3-b363-3b7fe8e74483');
  const registryId = tailId('Microsoft.ContainerRegistry/registries', config.registry);
  await arm('PUT', registryId, '2025-11-01', { location: config.location, tags: tags('Tailspin Toys'),
    sku: { name: 'Basic' }, properties: { adminUserEnabled: false, anonymousPullEnabled: false,
      publicNetworkAccess: 'Enabled', policies: { quarantinePolicy: { status: 'disabled' } } } });
  await waitResource(registryId, '2025-11-01');
  for (const identity of [config.workerIdentity, config.controlIdentity]) await role(registryId, identity.principalId, '7f951dda-4ed3-4680-a7ca-43fe172d538d');
  // Controller can manage only this demo's Contoso group, never any existing resource.
  await role(rgId(config.contosoGroup), config.controlIdentity.principalId, 'b24988ac-6180-42a0-ab88-20f7382dd24c');
  await role(config.workerIdentity.id, config.controlIdentity.principalId, 'f1a07417-d97a-45cb-824c-7a7467783830');
  const maaId = tailId('Microsoft.Attestation/attestationProviders', config.attestation);
  const maa = await arm('PUT', maaId, '2021-06-01', { location: config.location,
    tags: tags('Tailspin Toys'), properties: {} });
  config.maaEndpoint = maa.properties?.attestUri || `https://${config.attestation}.${config.location}.attest.azure.net`;
  await save('deployment.json', config);
  const workspaceId = tailId('Microsoft.OperationalInsights/workspaces', `tailspin-security-${config.suffix}`);
  await arm('PUT', workspaceId, '2025-07-01', { location: config.location, tags: tags('Tailspin Toys'),
    properties: { sku: { name: 'PerGB2018' }, retentionInDays: 30, workspaceCapping: { dailyQuotaGb: 1 } } });
  await arm('PUT', `${vaultId}/providers/Microsoft.Insights/diagnosticSettings/tailspin-key-audit`, '2021-05-01-preview', {
    properties: { workspaceId, logs: [{ category: 'AuditEvent', enabled: true }], metrics: [] }
  });
  config.workspaceId = workspaceId;
  await save('deployment.json', config);
}
async function certificates() {
  await mkdir(path.join(generated, 'certs'), { recursive: true });
  const exists = async (name) => {
    try { await access(path.join(generated, 'certs', name)); return true; }
    catch (error) { if (error.code !== 'ENOENT') throw error; return false; }
  };
  const mount = `type=bind,source=${path.join(generated, 'certs')},target=/certs`;
  if (!await exists('demo-ca.crt')) {
    run('docker', ['run', '--rm', '--mount', mount, 'alpine/openssl', 'req', '-x509', '-newkey', 'rsa:3072',
      '-nodes', '-keyout', '/certs/ca.key', '-out', '/certs/demo-ca.crt', '-days', '30',
      '-subj', '/CN=Tailspin Toys IP Demo CA', '-addext', 'basicConstraints=critical,CA:TRUE']);
  }
  for (const [name, url] of [['worker', config.workerUrl], ['tailspin', config.tailspinUrl]]) {
    if (await exists(`${name}.crt`) && await exists(`${name}.key`)) continue;
    const hostname = new URL(url).hostname;
    await writeFile(path.join(generated, 'certs', `${name}.ext`), `subjectAltName=DNS:${hostname},DNS:localhost\nextendedKeyUsage=serverAuth\n`);
    run('docker', ['run', '--rm', '--mount', mount, 'alpine/openssl', 'req', '-newkey', 'rsa:3072', '-nodes',
      '-keyout', `/certs/${name}.key`, '-out', `/certs/${name}.csr`, '-subj', `/CN=${hostname}`]);
    run('docker', ['run', '--rm', '--mount', mount, 'alpine/openssl', 'x509', '-req', '-in', `/certs/${name}.csr`,
      '-CA', '/certs/demo-ca.crt', '-CAkey', '/certs/ca.key', '-CAcreateserial', '-out', `/certs/${name}.crt`,
      '-days', '14', '-extfile', `/certs/${name}.ext`]);
  }
}
async function build(roleName) {
  cli(['acr', 'login', '--name', config.registry]);
  const image = `${config.registry}.azurecr.io/${roleName}:${config.suffix}`;
  run('docker', ['build', '--platform', 'linux/amd64', '--build-arg', `ROLE=${roleName}`,
    '-t', image, '-f', path.join(root, 'infra', 'Dockerfile'), root], { stdio: 'inherit' });
  // Smoke-test each exact built image locally with no Azure credentials or secrets.
  run('docker', ['run', '--rm', '--entrypoint', 'node', image, '--test'], { stdio: 'inherit' });
  run('docker', ['push', image], { stdio: 'inherit' });
  const data = JSON.parse(run('docker', ['image', 'inspect', image]));
  config[`${roleName}Image`] = data[0].RepoDigests.find((entry) => entry.startsWith(`${config.registry}.azurecr.io/`));
  if (!config[`${roleName}Image`]) throw new Error('Image push did not produce immutable digest');
  await save('deployment.json', config);
}
async function template(roleName) {
  const isWorker = roleName === 'worker';
  const identity = isWorker ? config.workerIdentity : config.controlIdentity;
  const environment = {
    OPERATOR_USERNAME: config.operatorUsername, OPERATOR_PASSWORD_HASH: config.operatorPasswordHash,
    AZURE_CLIENT_ID: identity.clientId, VAULT_URL: config.vaultUrl, MAA_ENDPOINT: config.maaEndpoint,
    TAILSPIN_URL: config.tailspinUrl, WORKER_URL: config.workerUrl, WORKER_KEY_NAME: 'contoso-robot',
    SELF_KEY_NAME: 'tailspin-control', NODE_EXTRA_CA_CERTS: '/app/certs/demo-ca.crt',
    WORKER_RESOURCE_ID: config.workerResourceId, WORKER_API_VERSION: api,
    APPLICATION_ENTRYPOINT: isWorker ? './server.mjs' : './src/server.js'
  };
  if (!isWorker) environment.WORKER_POLICY_HASH = config.workerPolicyHash;
  environment.TLS_CERT_B64 = (await readFile(path.join(generated, 'certs', `${isWorker ? 'worker' : 'tailspin'}.crt`))).toString('base64');
  environment.TLS_ENVELOPE = JSON.stringify(config[`${roleName}TransportEnvelope`]);
  environment.TLS_KEY_NAME = `${roleName}-transport`;
  const cg = {
    type: 'Microsoft.ContainerInstance/containerGroups', apiVersion: api,
    name: isWorker ? config.workerName : config.controlName, location: config.location,
    tags: tags(isWorker ? 'Contoso' : 'Tailspin Toys'),
    identity: { type: 'UserAssigned', userAssignedIdentities: { [identity.id]: {} } },
    properties: {
      sku: 'Confidential', osType: 'Linux', restartPolicy: 'Always',
      imageRegistryCredentials: [{ server: `${config.registry}.azurecr.io`, identity: identity.id }],
      containers: [{
        name: isWorker ? 'tailspin-robot' : 'tailspin-control',
        properties: { image: config[`${roleName}Image`], command: ['node', 'bootstrap.mjs'],
          ports: [{ port: 8443, protocol: 'TCP' }],
          resources: { requests: { cpu: 1, memoryInGB: 2 } },
          environmentVariables: Object.entries(environment).map(([name, value]) => ({ name, value }))
        }
      }, {
        name: 'tailspin-attestation',
        properties: { image: config.sidecarImage, command: ['/skr.sh'],
          environmentVariables: [{ name: 'Port', value: '8080' }, { name: 'LogLevel', value: 'error' }],
          resources: { requests: { cpu: 1, memoryInGB: 2 } } }
      }],
      ipAddress: { type: 'Public', dnsNameLabel: isWorker ? config.workerName : config.controlName,
        ports: [{ port: 8443, protocol: 'TCP' }] },
      confidentialComputeProperties: { ccePolicy: '' }
    }
  };
  const file = `${roleName}-arm.json`;
  await save(file, { $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
    contentVersion: '1.0.0.0', resources: [cg] });
  console.log(`Generating enforced CCE policy for ${roleName} (no exec, stdio or runtime logging)`);
  cli(['confcom', 'acipolicygen', '-a', path.join(generated, file), '--disable-stdio', '--approve-wildcards']);
  const approved = JSON.parse(await readFile(path.join(generated, file), 'utf8')).resources[0];
  // confcom also measures the infrastructure /pause container.
  const { source: rego, hash } = verifyPolicy(approved.properties.confidentialComputeProperties.ccePolicy, 3);
  config[`${roleName}PolicyHash`] = hash;
  await save(`${roleName}.rego`, rego);
  await save(`${roleName}.json`, approved);
  await save('deployment.json', config);
  return approved;
}
async function key(name, hostdata, identityId) {
  const release = { version: '1.0.0', anyOf: [{ authority: config.maaEndpoint, allOf: [
    { claim: 'x-ms-attestation-type', equals: 'sevsnpvm' },
    { claim: 'x-ms-compliance-status', equals: 'azure-compliant-uvm' },
    { claim: 'x-ms-sevsnpvm-is-debuggable', equals: 'false' },
    { claim: 'x-ms-sevsnpvm-hostdata', equals: hostdata }
  ] }] };
  await save(`${name}-release-policy.json`, release);
  const url = `${config.vaultUrl}/keys/${name}`;
  const existing = await request('GET', `${url}?api-version=7.4`, undefined, 'https://vault.azure.net', true);
  const body = { kty: 'RSA-HSM', key_size: 2048, key_ops: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
    attributes: { enabled: true, exportable: true },
    release_policy: { contentType: 'application/json; charset=utf-8', data: Buffer.from(JSON.stringify(release)).toString('base64url'), immutable: false },
    tags: tags('Tailspin Toys') };
  if (!existing) await request('POST', `${url}/create?api-version=7.4`, body, 'https://vault.azure.net');
  else {
    // Release policies apply to the key, not an individual key version.
    await request('PATCH', `${url}?api-version=7.4`, {
      release_policy: body.release_policy
    }, 'https://vault.azure.net');
    await request('PATCH', `${existing.key.kid}?api-version=7.4`, {
      attributes: { enabled: true }, tags: body.tags
    }, 'https://vault.azure.net');
  }
  // Release role is scoped to one key; the robot cannot read secrets, decrypt via vault, or update policy.
  await role(`${tailId('Microsoft.KeyVault/vaults', config.vault)}/keys/${name}`, identityId,
    '08bbd89e-9f13-488c-ac41-acfcb10c90ab');
}
async function prepareTransport(roleName, identityId) {
  const name = `${roleName}-transport`;
  const existing = await request('GET', `${config.vaultUrl}/keys/${name}?api-version=7.4`,
    undefined, 'https://vault.azure.net', true);
  if (!existing) await key(name, '0'.repeat(64), identityId);
  const { key: publicJwk } = existing || await request('GET',
    `${config.vaultUrl}/keys/${name}?api-version=7.4`, undefined, 'https://vault.azure.net');
  const plaintext = await readFile(path.join(generated, 'certs', `${roleName === 'worker' ? 'worker' : 'tailspin'}.key`));
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const aad = Buffer.from(`Tailspin transport ${config.suffix} ${roleName}`);
  try {
    const cipher = createCipheriv('aes-256-gcm', dek, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    config[`${roleName}TransportEnvelope`] = {
      algorithm: 'A256GCM', keyId: publicJwk.kid,
      wrappedKey: publicEncrypt({ key: createPublicKey({ key: { ...publicJwk, kty: 'RSA' }, format: 'jwk' }),
        padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, dek).toString('base64'),
      iv: iv.toString('base64'), aad: aad.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64')
    };
  } finally { dek.fill(0); plaintext.fill(0); }
}
async function deploy() {
  if (!config.workspaceId || !config.workerIdentity || !config.controlIdentity) throw new Error('Run foundation first');
  await certificates();
  await mkdir(path.join(generated, 'deploy'), { recursive: true });
  run('docker', ['pull', '--platform', 'linux/amd64', 'mcr.microsoft.com/aci/skr:2.12'], { stdio: 'inherit' });
  const sidecar = JSON.parse(run('docker', ['image', 'inspect', 'mcr.microsoft.com/aci/skr:2.12']));
  config.sidecarImage = sidecar[0].RepoDigests.find((digest) => digest.startsWith('mcr.microsoft.com/aci/skr@'));
  await prepareTransport('worker', config.workerIdentity.principalId);
  await build('worker');
  const worker = await template('worker');
  await key('worker-transport', config.workerPolicyHash, config.workerIdentity.principalId);
  await key('contoso-robot', config.workerPolicyHash, config.workerIdentity.principalId);
  // The exact approved worker PUT body is baked into the measured controller image.
  await mkdir(path.join(generated, 'deploy'), { recursive: true });
  const { type: _type, apiVersion: _version, name: _name, ...workerBody } = worker;
  await writeFile(path.join(generated, 'deploy', 'worker.json'), JSON.stringify(workerBody));
  await prepareTransport('tailspin', config.controlIdentity.principalId);
  await build('tailspin');
  const controller = await template('tailspin');
  await key('tailspin-transport', config.tailspinPolicyHash, config.controlIdentity.principalId);
  await key('tailspin-control', config.tailspinPolicyHash, config.controlIdentity.principalId);
  for (const [id, resource] of [[config.controlResourceId, controller], [config.workerResourceId, worker]]) {
    const { type: _type, apiVersion: _version, name: _name, ...body } = resource;
    await arm('PUT', id, api, body);
  }
  await Promise.all([waitResource(config.controlResourceId, api), waitResource(config.workerResourceId, api)]);
}
await init();
const phase = process.argv[2] || 'foundation';
if (phase === 'foundation') await foundation();
else if (phase === 'deploy') await deploy();
else if (phase === 'certificates') await certificates();
else throw new Error('Usage: node infra/deploy.mjs foundation|certificates|deploy');
console.log(deploymentSummary(config, phase));
