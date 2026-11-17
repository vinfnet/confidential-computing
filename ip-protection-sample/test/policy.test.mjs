import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyPolicy } from '../infra/policy.mjs';

function policy(change = {}, flags = '') {
  const container = { allow_stdio_access: false, allow_elevated: false, exec_processes: [] };
  const source = `package policy
containers := ${JSON.stringify([container, { ...container, ...change }])}
allow_dump_stacks := false
allow_runtime_logging := false
${flags}`;
  return { source, encoded: Buffer.from(source).toString('base64') };
}

test('release hash binds the exact decoded CCE bytes, not a normalized policy', () => {
  const { source, encoded } = policy();
  assert.deepEqual(verifyPolicy(encoded, 2), {
    source, hash: createHash('sha256').update(Buffer.from(source)).digest('hex')
  });
  assert.notEqual(verifyPolicy(policy({}, '\n').encoded, 2).hash, verifyPolicy(encoded, 2).hash);
});

test('deny exec, stdio and elevated access on every container, not just the first', () => {
  for (const change of [
    { allow_stdio_access: true }, { allow_elevated: true },
    { exec_processes: [{ command: ['/bin/sh'] }] }, { exec_processes: null }
  ]) assert.throws(() => verifyPolicy(policy(change).encoded, 2), /every measured container/);
});

test('wrong workload count and unknown policy format fail closed', () => {
  assert.throws(() => verifyPolicy(policy().encoded, 1), /every measured container/);
  assert.throws(() => verifyPolicy(Buffer.from('allow_all := true').toString('base64'), 2), /Unrecognized/);
});

test('runtime logging and stack dumps must both be explicitly disabled', () => {
  for (const setting of ['allow_dump_stacks', 'allow_runtime_logging']) {
    const unsafe = policy().source.replace(`${setting} := false`, `${setting} := true`);
    assert.throws(() => verifyPolicy(Buffer.from(unsafe).toString('base64'), 2), /CCE must disable/);
  }
});
