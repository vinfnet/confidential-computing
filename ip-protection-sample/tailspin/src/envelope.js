import { constants, createCipheriv, createPublicKey, publicEncrypt, randomBytes } from 'node:crypto';
import { AppError } from './security.js';

function publicJwk(key) {
  const value = key?.key;
  if (!value || !['RSA', 'RSA-HSM'].includes(value.kty) || !value.n || !value.e ||
      key.properties?.enabled === false || !key.id) throw new AppError(503, 'worker_key_unavailable');
  return {
    kty: 'RSA',
    n: typeof value.n === 'string' ? value.n : Buffer.from(value.n).toString('base64url'),
    e: typeof value.e === 'string' ? value.e : Buffer.from(value.e).toString('base64url')
  };
}

export function encryptCommands(jwk, keyId, sequence) {
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const issuedAt = new Date().toISOString();
  const aad = Buffer.from(JSON.stringify({ sequence, issuedAt, keyId }));
  const plaintext = Buffer.from(JSON.stringify({
    fictional: true,
    product: 'Tailspin Skylark toy airplane',
    operation: '3D_PRINT_TOY',
    units: 'mm',
    dimensions: { length: 142, wingspan: 168, height: 46 },
    material: 'fictional recycled polymer',
    layerHeight: 0.2,
    infillPercent: 18,
    safety: 'Synthetic demonstration instructions; not for physical manufacturing.',
    batch: `DEMO-${sequence}`,
    commands: [
      'SIMULATION_BEGIN: load the fictional Skylark assembly recipe',
      'VERIFY_DESIGN: compare toy geometry with the approved demo revision',
      'SELECT_PALETTE: choose ocean blue, cloud white and sunshine yellow',
      'PREVIEW_WORKSPACE: display the virtual print bed',
      'CHECK_MATERIAL: confirm fictional recycled polymer is available',
      'STAGE_FUSELAGE: position the virtual airplane body',
      'PREVIEW_LAYER: outline the lower fuselage shell',
      'SIMULATE_PRINT: render the lower fuselage shell',
      'SIMULATE_INFILL: add the fictional lightweight internal lattice',
      'PREVIEW_LAYER: outline the upper fuselage shell',
      'SIMULATE_PRINT: render the upper fuselage shell',
      'STAGE_LEFT_WING: position the virtual port wing',
      'SIMULATE_PRINT: render the left wing surface',
      'PREVIEW_MARKING: add a white cloud to the left wing',
      'STAGE_RIGHT_WING: position the virtual starboard wing',
      'SIMULATE_PRINT: render the right wing surface',
      'PREVIEW_MARKING: add a white cloud to the right wing',
      'STAGE_TAIL: position the virtual tail assembly',
      'SIMULATE_PRINT: render the horizontal tail surface',
      'SIMULATE_PRINT: render the vertical tail surface',
      'PREVIEW_MARKING: add the Tailspin star to the tail',
      'STAGE_CANOPY: prepare the fictional cockpit cover',
      'SIMULATE_FINISH: apply a sunshine-yellow canopy accent',
      'VIRTUAL_ASSEMBLY: align the wings with the fuselage',
      'VIRTUAL_ASSEMBLY: align the tail with the fuselage',
      'VIRTUAL_ASSEMBLY: place the canopy on the toy body',
      'VISUAL_INSPECTION: compare the virtual wings for symmetry',
      'VISUAL_INSPECTION: check the fictional surface finish',
      'DESIGN_INSPECTION: confirm the demo dimensions match the recipe',
      'PREVIEW_LABEL: prepare the fictional batch identifier',
      'PREVIEW_PACKAGING: display the recyclable toy carton',
      'VIRTUAL_PACK: place the rendered airplane in the demo carton',
      'RECORD_DEMO_RESULT: mark the simulated assembly complete',
      'SIMULATION_END: no physical robot commands were transmitted'
    ].map((instruction, index) => ({ step: index + 1, instruction }))
  }, null, 2));
  try {
    const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
    if (publicKey.asymmetricKeyDetails.modulusLength < 2048) throw new AppError(503, 'worker_key_invalid');
    const wrappedKey = publicEncrypt({
      key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'
    }, dek);
    const cipher = createCipheriv('aes-256-gcm', dek, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      algorithm: 'A256GCM', keyId, wrappedKey: wrappedKey.toString('base64'),
      iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'), aad: aad.toString('base64'), sequence, issuedAt
    };
  } finally { dek.fill(0); plaintext.fill(0); }
}

export function createEnvelopeService(config, keyClient, now = Date.now) {
  let cache;
  let expires = 0;
  let sequence = 0;
  let epoch = 0;
  let pending;
  return {
    invalidate() { cache = undefined; expires = 0; epoch++; },
    async get() {
      if (cache && now() < expires) return cache;
      if (pending) return pending;
      const currentEpoch = epoch;
      pending = (async () => {
        const key = await keyClient.getKey(config.workerKeyName);
        const jwk = publicJwk(key);
        const id = new URL(key.id);
        const parts = id.pathname.split('/');
        if (id.origin !== config.vaultUrl || parts.length !== 4 ||
            parts[1] !== 'keys' || parts[2] !== config.workerKeyName || !parts[3] ||
            id.search || id.hash) throw new AppError(503, 'worker_key_invalid');
        const envelope = encryptCommands(jwk, key.id, ++sequence);
        if (epoch !== currentEpoch) throw new AppError(503, 'worker_key_changed');
        cache = envelope;
        expires = now() + 30000;
        return envelope;
      })().finally(() => { pending = undefined; });
      return pending;
    }
  };
}
