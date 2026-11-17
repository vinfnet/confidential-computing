export function deploymentSummary(config, phase) {
  const groupId = (name) => `/subscriptions/${config.subscriptionId}/resourceGroups/${name}`;
  const portal = (id) => `https://portal.azure.com/#@${encodeURIComponent(config.tenantId)}/resource${id}`;
  const tailspinGroupId = groupId(config.tailspinGroup);
  return [
    `\n${phase} completed. Important demo URLs:`,
    `Tailspin dashboard: ${config.tailspinUrl}`,
    `Contoso-hosted worker: ${config.workerUrl}`,
    `Worker ciphertext/status (public; no plaintext): ${new URL('/api/ciphertext', config.workerUrl).href}`,
    `Public demo CA certificate: ${new URL('/demo-ca.crt', config.tailspinUrl).href}`,
    `Tailspin resource group: ${portal(tailspinGroupId)}`,
    `Contoso resource group: ${portal(groupId(config.contosoGroup))}`,
    `Key Vault: ${config.vaultUrl}`,
    `Attestation: ${config.maaEndpoint}`,
    `Container registry: https://${config.registry}.azurecr.io`,
    `Security logs workspace: ${portal(config.workspaceId)}`,
    '',
    'Application URLs require a successful deploy and attested HTTPS bootstrap.',
    'Explicitly trust .generated/certs/demo-ca.crt before opening the HTTPS pages.',
    'Operator credentials remain private in .generated/operator-credentials.json; no credentials are printed.'
  ].join('\n');
}
