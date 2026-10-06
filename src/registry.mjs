import fs from 'node:fs';
import crypto from 'node:crypto';
import { AppError, ErrorCode } from './errors.mjs';

/**
 * Device key registry declared with the deployment (config/device-keys.json).
 *
 * File shape:
 * {
 *   "devices": {
 *     "<deviceId>": { "keyId": "<id>", "publicKey": "<base64 32-byte Ed25519 raw or PEM or JWK>" }
 *   },
 *   "keys": {
 *     "<keyId>": "<base64 32-byte Ed25519 raw key | PEM | JWK object>"
 *   }
 * }
 *
 * Both sections are optional. A key listed under devices[].keyId must exist in
 * keys. Entries directly under devices may also inline the public key.
 */
export class DeviceRegistry {
  constructor({ devices = new Map(), keys = new Map() } = {}) {
    // keyId -> { keyObject, deviceId? }  (deviceId set when key is device-bound)
    this.keys = keys;
    // deviceId -> { keyId, keyObject }
    this.devices = devices;
  }

  static fromFile(file) {
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (err) {
      throw new Error(`Cannot read device keys file ${file}: ${err.message}`);
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      throw new Error(`Device keys file ${file} is not valid JSON: ${err.message}`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error(`Device keys file ${file} must contain a JSON object`);
    }
    return DeviceRegistry.fromManifest(parsed);
  }

  static fromManifest(manifest) {
    const rawKeys = manifest.keys ?? {};
    const rawDevices = manifest.devices ?? {};
    if (typeof rawKeys !== 'object' || rawKeys === null || Array.isArray(rawKeys)) {
      throw new Error('"keys" must be an object mapping keyId -> public key');
    }
    if (typeof rawDevices !== 'object' || rawDevices === null || Array.isArray(rawDevices)) {
      throw new Error('"devices" must be an object mapping deviceId -> { keyId, publicKey? }');
    }

    const keys = new Map();
    for (const [keyId, material] of Object.entries(rawKeys)) {
      keys.set(keyId, { keyObject: importPublicKey(material, keyId) });
    }

    const devices = new Map();
    for (const [deviceId, entry] of Object.entries(rawDevices)) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
        throw new Error(`devices.${deviceId} must be an object`);
      }
      const keyId = entry.keyId;
      if (typeof keyId !== 'string' || keyId.length === 0) {
        throw new Error(`devices.${deviceId}.keyId must be a non-empty string`);
      }
      let record = keys.get(keyId);
      if (!record) {
        if (entry.publicKey === undefined) {
          throw new Error(`devices.${deviceId}: keyId "${keyId}" not found in keys and no inline publicKey provided`);
        }
        record = { keyObject: importPublicKey(entry.publicKey, keyId) };
        keys.set(keyId, record);
      }
      if (record.deviceId !== undefined && record.deviceId !== deviceId) {
        throw new Error(`keyId "${keyId}" is bound to multiple devices (${record.deviceId}, ${deviceId})`);
      }
      record.deviceId = deviceId;
      devices.set(deviceId, { keyId, keyObject: record.keyObject });
    }

    return new DeviceRegistry({ devices, keys });
  }

  /** Returns { keyObject, boundDeviceId? } or null for an unknown keyId. */
  lookupKey(keyId) {
    if (typeof keyId !== 'string') return null;
    return this.keys.get(keyId) ?? null;
  }

  lookupDevice(deviceId) {
    return this.devices.get(deviceId) ?? null;
  }
}

/**
 * Accepts an Ed25519 public key as:
 *  - base64 of the raw 32-byte key (preferred, compact on the wire/file)
 *  - PEM string (SPKI)
 *  - JWK object (OKP / Ed25519)
 */
function importPublicKey(material, keyId) {
  if (material && typeof material === 'object' && material.kty) {
    return crypto.createPublicKey({ key: material, format: 'jwk' });
  }
  if (typeof material === 'string') {
    const trimmed = material.trim();
    if (trimmed.includes('-----BEGIN')) {
      return crypto.createPublicKey(trimmed);
    }
    const buf = decodeBase64(trimmed, `keys.${keyId}`);
    if (buf.length !== 32) {
      throw new Error(`keys.${keyId}: raw Ed25519 public key must be 32 bytes, got ${buf.length}`);
    }
    return createEd25519FromRaw(buf);
  }
  throw new Error(`keys.${keyId}: unsupported public key material`);
}

// DER header for an Ed25519 public key in SubjectPublicKeyInfo form.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function createEd25519FromRaw(raw32) {
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw32]),
    format: 'der',
    type: 'spki',
  });
}

function decodeBase64(text, label) {
  try {
    return Buffer.from(text, 'base64');
  } catch (err) {
    throw new Error(`${label} is not valid base64: ${err.message}`);
  }
}

/**
 * Verify an Ed25519 signature over the exact payload bytes.
 * Never throws for a "bad" signature — returns false. Throws only for an
 * unknown key (caller maps that to UNKNOWN_KEY) or malformed signature
 * envelope (caller maps to INVALID_REQUEST).
 */
export function verifyEd25519(keyObject, payload, signatureBytes) {
  if (!(signatureBytes instanceof Buffer) || signatureBytes.length !== 64) {
    throw new AppError(400, ErrorCode.INVALID_REQUEST, 'signatureBase64 must decode to a 64-byte Ed25519 signature');
  }
  if (!crypto.verify(null, Buffer.from(payload), keyObject, signatureBytes)) {
    return false;
  }
  return true;
}

export function generateEd25519KeyPair() {
  return crypto.generateKeyPairSync('ed25519');
}

/** Raw 32-byte public key encoded as base64, for registry files. */
export function publicKeyRawBase64(keyObject) {
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32).toString('base64');
}
