import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, createCipheriv, publicEncrypt, constants } from 'node:crypto';
import { ProtectedState, decryptEnvelope } from '../protection.mjs';

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const vault = 'https://tailspin.vault.azure.net';
function envelope() {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const aad = Buffer.from('Tailspin Toys / Contoso / robot-01');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update('PRINT TOY AIRPLANE'), cipher.final()]);
  return { algorithm: 'A256GCM', keyId: `${vault}/keys/contoso-robot/${'a'.repeat(32)}`,
    wrappedKey: publicEncrypt({ key: pair.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key).toString('base64'),
    iv: iv.toString('base64'), aad: aad.toString('base64'), tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64') };
}
test('real RSA-OAEP-256 + AES-256-GCM roundtrip', () => {
  assert.equal(decryptEnvelope(envelope(), pair.privateKey.export({ format: 'jwk' }), vault, 'contoso-robot').toString(), 'PRINT TOY AIRPLANE');
});
test('tampering with ciphertext or AAD prevents plaintext', () => {
  for (const field of ['ciphertext', 'aad', 'tag']) {
    const data = envelope();
    const bytes = Buffer.from(data[field], 'base64'); bytes[0] ^= 1; data[field] = bytes.toString('base64');
    assert.throws(() => decryptEnvelope(data, pair.privateKey.export({ format: 'jwk' }), vault, 'contoso-robot'));
  }
});
test('another vault, key, or malformed version is rejected', () => {
  const data = envelope();
  for (const keyId of ['https://evil.vault.azure.net/keys/contoso-robot/' + 'a'.repeat(32), `${vault}/keys/control/${'a'.repeat(32)}`, `${data.keyId}/extra`]) {
    assert.throws(() => decryptEnvelope({ ...data, keyId }, pair.privateKey.export({ format: 'jwk' }), vault, 'contoso-robot'));
  }
});
test('lease expires at exact deadline and zeroes plaintext memory', () => {
  let now = 1000;
  const state = new ProtectedState(() => now, 12000);
  const plaintext = Buffer.from('secret');
  state.accept({ ciphertext: 'encrypted' }, plaintext);
  now = 12999; assert.equal(state.snapshot().plaintext, 'secret');
  now = 13000; assert.equal(state.snapshot().plaintext, null);
  assert.ok(plaintext.every((b) => b === 0));
  assert.equal(state.snapshot().envelope.ciphertext, 'encrypted');
});
test('key loss clears plaintext immediately, preserving only ciphertext', () => {
  const state = new ProtectedState();
  state.accept({ ciphertext: 'encrypted' }, Buffer.from('secret'));
  state.clear('Key revoked');
  assert.equal(state.snapshot().state, 'unavailable');
  assert.equal(state.snapshot().plaintext, null);
  assert.equal(state.snapshot().reason, 'Key revoked');
});
test('plaintext buffer is cleared at expiry without an HTTP reader', async () => {
  const state = new ProtectedState(Date.now, 20);
  const plaintext = Buffer.from('secret');
  state.accept({ ciphertext: 'encrypted' }, plaintext);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.ok(plaintext.every((b) => b === 0));
  assert.equal(state.snapshot().plaintext, null);
});
