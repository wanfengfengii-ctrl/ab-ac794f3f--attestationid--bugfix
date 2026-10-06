import { Buffer } from 'node:buffer';
import { AppError, ErrorCode } from './errors.mjs';
import { verifyEd25519 } from './registry.mjs';
import { sha256Hex, sameAttestationIdentity } from './store.mjs';

const MAX_ID_CHARS = 256;
const LOWER_SHA256 = /^[0-9a-f]{64}$/;
const STRICT_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

const textDecoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Strict base64 decode: rejects embedded junk and non-canonical padding,
 * unlike Buffer.from(s, 'base64') which silently skips invalid characters.
 */
export function decodeBase64Strict(value, field) {
  if (typeof value !== 'string') {
    throw new AppError(400, ErrorCode.INVALID_REQUEST, `${field} must be a base64 string`);
  }
  if (value.length === 0 || value.length % 4 !== 0 || !STRICT_BASE64.test(value)) {
    throw new AppError(400, ErrorCode.INVALID_REQUEST, `${field} is not valid canonical base64`);
  }
  const buf = Buffer.from(value, 'base64');
  if (buf.toString('base64') !== value) {
    throw new AppError(400, ErrorCode.INVALID_REQUEST, `${field} is not valid canonical base64`);
  }
  return buf;
}

/** Parse and strictly validate the inner attestation JSON payload. */
export function parsePayload(rawBytes, maxPayloadBytes) {
  if (rawBytes.length === 0) {
    throw new AppError(400, ErrorCode.INVALID_PAYLOAD, 'payload is empty');
  }
  if (rawBytes.length > maxPayloadBytes) {
    throw new AppError(400, ErrorCode.INVALID_PAYLOAD, `payload exceeds ${maxPayloadBytes} bytes`);
  }

  let text;
  try {
    text = textDecoder.decode(rawBytes);
  } catch {
    throw new AppError(400, ErrorCode.INVALID_PAYLOAD, 'payload is not valid UTF-8');
  }

  let obj;
  try {
    obj = JSON.parse(text);
  } catch (err) {
    throw new AppError(400, ErrorCode.INVALID_PAYLOAD, `payload is not valid JSON: ${err.message}`);
  }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new AppError(400, ErrorCode.INVALID_PAYLOAD, 'payload JSON must be an object');
  }

  const deviceId = obj.deviceId;
  if (typeof deviceId !== 'string' || deviceId.length === 0 || deviceId.length > MAX_ID_CHARS) {
    throw new AppError(400, ErrorCode.INVALID_PAYLOAD, 'payload.deviceId must be a non-empty string');
  }
  const generation = obj.generation;
  if (!Number.isSafeInteger(generation) || generation < 1) {
    throw new AppError(400, ErrorCode.INVALID_PAYLOAD, 'payload.generation must be a positive integer');
  }
  const previousGeneration = obj.previousGeneration;
  if (!Number.isSafeInteger(previousGeneration) || previousGeneration < 0) {
    throw new AppError(400, ErrorCode.INVALID_PAYLOAD, 'payload.previousGeneration must be a non-negative integer');
  }
  const configSha256 = obj.configSha256;
  if (typeof configSha256 !== 'string' || !LOWER_SHA256.test(configSha256)) {
    throw new AppError(400, ErrorCode.INVALID_PAYLOAD, 'payload.configSha256 must be 64 lowercase hex characters (SHA-256)');
  }

  return { deviceId, generation, previousGeneration, configSha256, raw: rawBytes };
}

function validateEnvelopeFields(body) {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new AppError(400, ErrorCode.INVALID_REQUEST, 'request body must be a JSON object');
  }
  const { attestationId, keyId } = body;
  if (typeof attestationId !== 'string' || attestationId.length === 0 || attestationId.length > MAX_ID_CHARS) {
    throw new AppError(400, ErrorCode.INVALID_REQUEST, 'attestationId must be a non-empty string');
  }
  if (typeof keyId !== 'string' || keyId.length === 0 || keyId.length > MAX_ID_CHARS) {
    throw new AppError(400, ErrorCode.INVALID_REQUEST, 'keyId must be a non-empty string');
  }
  return { attestationId, keyId };
}

/**
 * Core use case. All state transitions go through store.accept(), which
 * serializes decisions per device — verification happens before taking the
 * lock, but every state-changing decision is made atomically inside it.
 */
export function createAttestationService({ store, registry, maxPayloadBytes, clock = () => new Date() }) {
  async function submit(rawBody) {
    const { attestationId, keyId } = validateEnvelopeFields(rawBody);

    const payloadBytes = decodeBase64Strict(rawBody.payloadBase64, 'payloadBase64');
    const signatureBytes = decodeBase64Strict(rawBody.signatureBase64, 'signatureBase64');
    const payload = parsePayload(payloadBytes, maxPayloadBytes);

    // 1) Key must be a deployment-declared key.
    const keyRecord = registry.lookupKey(keyId);
    if (!keyRecord) {
      throw new AppError(401, ErrorCode.UNKNOWN_KEY, `keyId "${keyId}" is not registered`);
    }

    // 2) Signature is verified over the exact decoded payload bytes.
    if (!verifyEd25519(keyRecord.keyObject, payloadBytes, signatureBytes)) {
      throw new AppError(401, ErrorCode.INVALID_SIGNATURE, 'Ed25519 signature does not verify against payload');
    }

    // 3) Device-binding: a key provisioned for one device may not attest another.
    const declared = registry.lookupDevice(payload.deviceId);
    if (declared && declared.keyId !== keyId) {
      throw new AppError(
        403,
        ErrorCode.KEY_DEVICE_MISMATCH,
        `device "${payload.deviceId}" is registered to a different keyId`,
      );
    }
    if (!declared && keyRecord.deviceId !== undefined && keyRecord.deviceId !== payload.deviceId) {
      throw new AppError(
        403,
        ErrorCode.KEY_DEVICE_MISMATCH,
        `keyId "${keyId}" is bound to another device`,
      );
    }

    // 4) Atomic, per-device-serialized chain decision + durable append.
    const payloadSha256 = sha256Hex(payload.raw);
    const candidate = {
      deviceId: payload.deviceId,
      keyId,
      generation: payload.generation,
      previousGeneration: payload.previousGeneration,
      configSha256: payload.configSha256,
      payloadSha256,
    };
    const result = await store.accept(payload.deviceId, (head) => {
      // attestationId is a GLOBAL idempotency identity across all devices.
      const previous = store.findAcceptedAttestation(attestationId);
      if (previous) {
        if (sameAttestationIdentity(previous, candidate)) {
          return { action: 'replay', envelope: previous };
        }
        // Same attestation number, different content (or another device/key
        // or different signed bytes) -> conflict, no state change anywhere.
        return {
          action: 'reject',
          status: 409,
          code: ErrorCode.GENERATION_CONFLICT,
          message: 'attestationId was already accepted with different content',
          details: {
            attestationId,
            acceptedDeviceId: previous.deviceId,
            submittedDeviceId: payload.deviceId,
            acceptedGeneration: previous.generation,
            acceptedConfigSha256: previous.configSha256,
          },
        };
      }

      if (head === null) {
        // First submission for this device must root the chain at generation zero.
        if (payload.previousGeneration !== 0) {
          return {
            action: 'reject',
            status: 409,
            code: ErrorCode.PREDECESSOR_MISMATCH,
            message: `first attestation for device must have previousGeneration 0, got ${payload.previousGeneration}`,
            details: { expectedPreviousGeneration: 0, actual: payload.previousGeneration },
          };
        }
      } else {
        if (payload.previousGeneration !== head.generation) {
          return {
            action: 'reject',
            status: 409,
            code: ErrorCode.PREDECESSOR_MISMATCH,
            message: 'stale or forked predecessor; it must equal the currently accepted generation',
            details: {
              expectedPreviousGeneration: head.generation,
              actual: payload.previousGeneration,
            },
          };
        }
        if (payload.generation === head.generation) {
          return {
            action: 'reject',
            status: 409,
            code: ErrorCode.GENERATION_CONFLICT,
            message: 'a different configuration is already accepted at this generation',
            details: {
              generation: head.generation,
              acceptedConfigSha256: head.configSha256,
              submittedConfigSha256: payload.configSha256,
            },
          };
        }
        if (payload.generation < head.generation) {
          return {
            action: 'reject',
            status: 409,
            code: ErrorCode.GENERATION_NOT_ADVANCED,
            message: 'rollback rejected: generation is older than the accepted head',
            details: { headGeneration: head.generation, submittedGeneration: payload.generation },
          };
        }
      }

      const envelope = {
        attestationId,
        keyId,
        deviceId: payload.deviceId,
        generation: payload.generation,
        previousGeneration: payload.previousGeneration,
        configSha256: payload.configSha256,
        payloadSha256,
        configSize: payload.raw.length,
        acceptedAt: clock().toISOString(),
      };
      return { action: 'accept', envelope };
    });

    if (result.outcome === 'reject') {
      throw new AppError(result.status, result.code, result.message, result.details);
    }

    return {
      replayed: result.outcome === 'replay',
      accepted: {
        attestationId: result.envelope.attestationId,
        deviceId: result.envelope.deviceId,
        keyId: result.envelope.keyId,
        generation: result.envelope.generation,
        previousGeneration: result.envelope.previousGeneration,
        configSha256: result.envelope.configSha256,
        payloadSha256: result.envelope.payloadSha256,
        acceptedAt: result.envelope.acceptedAt,
      },
      head: store.head(payload.deviceId),
    };
  }

  function head(deviceId) {
    const h = store.head(deviceId);
    if (!h) {
      throw new AppError(404, ErrorCode.DEVICE_NOT_FOUND, `no accepted attestation for device "${deviceId}"`);
    }
    return h;
  }

  return { submit, head, sha256Hex, store };
}
