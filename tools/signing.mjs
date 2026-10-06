import crypto from 'node:crypto';

// DER prefixes for Ed25519 keys.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Build a public Ed25519 KeyObject from the raw 32-byte public key. */
export function publicKeyFromRaw(raw32) {
  if (raw32.length !== 32) throw new Error('raw Ed25519 public key must be 32 bytes');
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw32]),
    format: 'der',
    type: 'spki',
  });
}

/** Build a private Ed25519 KeyObject from its 32-byte seed. */
export function privateKeyFromSeed(seed32) {
  if (seed32.length !== 32) throw new Error('Ed25519 seed must be 32 bytes');
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed32]),
    format: 'der',
    type: 'pkcs8',
  });
}

export function rawPublic(keyObject) {
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32);
}

export function rawSeed(keyObject) {
  const der = keyObject.export({ type: 'pkcs8', format: 'der' });
  return der.subarray(der.length - 32);
}

export function generateDeviceKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicRaw: rawPublic(publicKey),
    seed: rawSeed(privateKey),
  };
}

/**
 * Sign the exact payload bytes (the signature object required by the API).
 * Returns base64 signature.
 */
export function signPayload(privateKeyObject, payloadBytes) {
  return crypto.sign(null, Buffer.from(payloadBytes), privateKeyObject).toString('base64');
}

export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function randomId(prefix) {
  return `${prefix}-${crypto.randomBytes(8).toString('hex')}`;
}
