import assert from 'node:assert/strict';
import test from 'node:test';
import { deploymentSummary } from './deployment-summary.mjs';

const config = {
  subscriptionId: 'test-subscription', tenantId: 'test-tenant',
  tailspinGroup: 'example-tailspin', contosoGroup: 'example-contoso',
  tailspinUrl: 'https://control.example.test:8443', workerUrl: 'https://worker.example.test:8443',
  vaultUrl: 'https://vault.example.test', maaEndpoint: 'https://attestation.example.test',
  registry: 'exampleregistry',
  workspaceId: '/subscriptions/test-subscription/resourceGroups/example-tailspin/providers/Microsoft.OperationalInsights/workspaces/security',
  upn: 'private-owner@example.test', operatorPasswordHash: 'secret-password-hash',
  workerTransportEnvelope: { ciphertext: 'private-envelope' }
};

test('deployment summary contains current deployment URLs and trust instructions for every phase', () => {
  for (const phase of ['foundation', 'certificates', 'deploy']) {
    const output = deploymentSummary(config, phase);
    assert.ok(output.startsWith(`\n${phase} completed.`));
    for (const value of [config.tailspinUrl, config.workerUrl, config.vaultUrl, config.maaEndpoint,
      'https://exampleregistry.azurecr.io', `${config.workerUrl}/api/ciphertext`,
      `${config.tailspinUrl}/demo-ca.crt`, '/resourceGroups/example-tailspin',
      '/resourceGroups/example-contoso', config.workspaceId, '.generated/certs/demo-ca.crt']) {
      assert.ok(output.includes(value), `Missing summary entry: ${value}`);
    }
    assert.ok(output.includes('require a successful deploy'));
  }
});

test('deployment summary never serializes private deployment values', () => {
  const output = deploymentSummary(config, 'deploy');
  for (const privateValue of [config.upn, config.operatorPasswordHash, config.workerTransportEnvelope.ciphertext]) {
    assert.ok(!output.includes(privateValue));
  }
});
