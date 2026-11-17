import { createDecipheriv, createPrivateKey, privateDecrypt, constants } from 'node:crypto';

export function decryptEnvelope(envelope, jwk, vaultUrl, keyName) {
  const expected = `${vaultUrl.replace(/\/$/, '')}/keys/${keyName}/`;
  if (envelope.algorithm !== 'A256GCM' || !envelope.keyId.startsWith(expected) ||
      !/^[a-f0-9]{32}$/i.test(envelope.keyId.slice(expected.length))) {
    throw new Error('Unapproved encryption key or algorithm');
  }
  const key = createPrivateKey({ key: jwk, format: 'jwk' });
  const dek = privateDecrypt({
    key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'
  }, Buffer.from(envelope.wrappedKey, 'base64'));
  try {
    if (dek.length !== 32) throw new Error('Invalid data encryption key');
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    if (iv.length !== 12 || tag.length !== 16) throw new Error('Invalid GCM envelope');
    const decipher = createDecipheriv('aes-256-gcm', dek, iv);
    decipher.setAAD(Buffer.from(envelope.aad, 'base64'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
  } finally {
    dek.fill(0);
  }
}

export class ProtectedState {
  constructor(clock = Date.now, leaseMs = 12000) {
    this.clock = clock;
    this.leaseMs = leaseMs;
    this.envelope = null;
    this.plaintext = null;
    this.expiresAt = 0;
    this.lastSuccess = null;
    this.error = 'Waiting for hardware attestation and secure key release';
  }
  clear(reason) {
    clearTimeout(this.expiryTimer);
    this.plaintext?.fill(0);
    this.plaintext = null;
    this.expiresAt = 0;
    this.error = reason;
  }
  accept(envelope, plaintext) {
    this.clear(null);
    this.envelope = envelope;
    this.plaintext = plaintext;
    this.expiresAt = this.clock() + this.leaseMs;
    this.lastSuccess = new Date(this.clock()).toISOString();
    this.expiryTimer = setTimeout(() => this.clear('Attestation/key-release lease expired'), this.leaseMs);
    this.expiryTimer.unref();
  }
  snapshot() {
    if (this.clock() >= this.expiresAt && this.plaintext) this.clear('Attestation/key-release lease expired');
    return {
      state: this.plaintext ? 'protected' : 'unavailable',
      plaintext: this.plaintext ? this.plaintext.toString('utf8') : null,
      envelope: this.envelope,
      expiresAt: this.expiresAt,
      lastSuccess: this.lastSuccess,
      reason: this.error
    };
  }
}
