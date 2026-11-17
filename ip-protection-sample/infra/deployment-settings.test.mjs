import assert from 'node:assert/strict';
import test from 'node:test';
import { assertDeploymentOwner, resourcePrefix } from './deployment-settings.mjs';

test('new deployment prefixes are portable and fit the Key Vault name limit', () => {
  assert.equal(resourcePrefix(), 'demo');
  for (const prefix of ['a', 'example', 'team1234']) {
    assert.equal(resourcePrefix(prefix), prefix);
    assert.ok(`${prefix}tailspin12345678`.length <= 24);
  }
  for (const prefix of ['', 'Upper', 'a-b', '1team', 'toolong123', ' x', 'x\n']) {
    assert.throws(() => resourcePrefix(prefix), /RESOURCE_PREFIX/);
  }
});

test('ownership remains pinned to the recorded deployment owner without a personal constant', () => {
  assert.doesNotThrow(() => assertDeploymentOwner('owner@example.test', 'owner@example.test'));
  assert.doesNotThrow(() => assertDeploymentOwner('Owner@Example.test', 'owner@example.test'));
  assert.throws(() => assertDeploymentOwner('owner@example.test', 'another@example.test'), /Unexpected deployment owner/);
  assert.doesNotThrow(() => assertDeploymentOwner('owner@example.test', 'another@example.test', true));
  for (const [recorded, current] of [[undefined, 'owner@example.test'], ['', 'owner@example.test'],
    ['owner@example.test', undefined], ['owner@example.test', ' ']]) {
    assert.throws(() => assertDeploymentOwner(recorded, current, true), /Cannot verify deployment ownership/);
  }
});
