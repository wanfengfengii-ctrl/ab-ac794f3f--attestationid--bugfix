import fs from 'node:fs/promises';
import fssync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { ErrorCode } from './errors.mjs';

/**
 * Fields that define the business content of an attestation. A repeated
 * attestationId replays the original result only when ALL of these match; in
 * particular payloadSha256 pins the exact signed byte sequence, so re-signed
 * JSON with extra fields or different bytes never replays.
 *
 * Records written before the byte-level pin existed have no payloadSha256;
 * when either side lacks it the byte check is skipped (they are still fully
 * distinguished by device/key/generation/configSha256).
 */
export const ATTESTATION_IDENTITY_FIELDS = Object.freeze([
  'deviceId',
  'keyId',
  'generation',
  'previousGeneration',
  'configSha256',
]);

export function sameAttestationIdentity(a, b) {
  const fieldsMatch = ATTESTATION_IDENTITY_FIELDS.every((field) => a[field] === b[field]);
  if (!fieldsMatch) return false;
  // Legacy records have no hash; compare bytes only when both sides know them.
  if (a.payloadSha256 === undefined || b.payloadSha256 === undefined) {
    return true;
  }
  return a.payloadSha256 === b.payloadSha256;
}

/**
 * Durable, append-only store of accepted attestations.
 *
 * Files under dataDir:
 *   configs/<deviceId>.log  per-device chain log, newest record last
 *   attestations.log        GLOBAL attestationId -> envelope index
 *
 * Every accepted envelope is written as one JSON line to BOTH files:
 *   {"attestationId","deviceId","keyId","generation","previousGeneration",
 *    "configSha256","payloadSha256","configSize","acceptedAt"}
 *
 * attestationId is a GLOBAL idempotency identity: the same number may be
 * accepted exactly once across every device. Same id + same identity replays
 * the original result; same id + any identity difference is a 409 conflict and
 * never creates or advances a head.
 *
 * Durability: both appends are flushed (fsync) before the API replies.
 * Restart: the global index is loaded, device logs are replayed against it,
 * the chain is revalidated, and the in-memory "head" is rebuilt so GET
 * .../head always reports the single accepted tip.
 *
 * Concurrency: accept() for the same device is serialized through a per-device
 * promise chain, and the final dedup + durable commit runs under one global
 * mutex. Concurrent requests for the same attestationId (even across devices)
 * therefore resolve to exactly one acceptance.
 */
export class AttestationStore {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.configsDir = path.join(dataDir, 'configs');
    // Global attestationId -> accepted envelope.
    this.attestations = new Map();
    this.indexFile = path.join(dataDir, 'attestations.log');
    this.indexChain = Promise.resolve();
    // deviceId -> {
    //   generation: number, configSha256: string, configSize: number,
    //   attestations: Map<attestationId, envelope>,
    //   file: string, chain: Promise
    // }
    this.devices = new Map();
  }

  async init() {
    await fs.mkdir(this.configsDir, { recursive: true });

    // Global index first: it is the authoritative attestationId dedup set.
    await this.recoverIndex();

    const names = await fs.readdir(this.configsDir).catch(() => []);
    const seenIds = new Set();
    for (const name of names) {
      if (!name.endsWith('.log')) continue;
      const deviceId = decodeDeviceFile(name);
      const file = path.join(this.configsDir, name);
      const state = {
        generation: 0,
        configSha256: null,
        configSize: 0,
        keyId: null,
        attestations: new Map(),
        file,
        chain: Promise.resolve(),
      };
      await this.recoverDeviceFile(state, seenIds);
      this.devices.set(deviceId, state);
    }

    // Every index entry must be backed by a device record (the device log is
    // appended first, so an orphan index means tampering or lost data).
    for (const id of this.attestations.keys()) {
      if (!seenIds.has(id)) {
        throw new Error(
          `Corrupt index ${this.indexFile}: attestationId "${id}" has no matching device log record`,
        );
      }
    }
  }

  head(deviceId) {
    const state = this.devices.get(deviceId);
    if (!state || state.generation === 0) return null;
    return {
      deviceId,
      generation: state.generation,
      configSha256: state.configSha256,
      configSize: state.configSize,
    };
  }

  listDevices() {
    return [...this.devices.keys()].filter((id) => this.devices.get(id).generation > 0);
  }

  /** Per-device lookup (used for isolation checks/tests). */
  findAttestation(deviceId, attestationId) {
    const state = this.devices.get(deviceId);
    return state?.attestations.get(attestationId) ?? null;
  }

  /** Global lookup: an attestationId accepted by ANY device. */
  findAcceptedAttestation(attestationId) {
    return this.attestations.get(attestationId) ?? null;
  }

  /**
   * Validate-then-append.
   *
   * decisionFn(existingHead) runs under the device mutex and must return:
   *   { action: 'accept', envelope: {...record fields} }
   *   { action: 'reject', status, code, message, details? }
   *   { action: 'replay', envelope: previousEnvelope }
   *
   * An 'accept' candidate is then re-checked against the GLOBAL attestationId
   * index under a process-wide mutex and durably committed to both logs; this
   * is where cross-device races for the same id are resolved (exactly one
   * wins). Rejections never touch any log or in-memory state.
   */
  accept(deviceId, decisionFn) {
    let state = this.devices.get(deviceId);
    if (!state) {
      const file = path.join(this.configsDir, encodeDeviceFile(deviceId));
      state = {
        generation: 0,
        configSha256: null,
        configSize: 0,
        keyId: null,
        attestations: new Map(),
        file,
        chain: Promise.resolve(),
      };
      this.devices.set(deviceId, state);
    }

    const run = state.chain.then(async () => {
      const existingHead =
        state.generation === 0
          ? null
          : { generation: state.generation, configSha256: state.configSha256 };
      const decision = await decisionFn(existingHead);

      if (decision.action === 'reject') {
        return { outcome: 'reject', ...stripAction(decision) };
      }
      if (decision.action === 'replay') {
        return { outcome: 'replay', envelope: decision.envelope };
      }

      // Global serialization: attestationId dedup + durable dual-log commit.
      return this.runIndexExclusive(async () => {
        const e = decision.envelope;
        const committed = this.attestations.get(e.attestationId);
        if (committed) {
          // Lost a race (same device retried concurrently, or another device
          // used the same number). Same identity replays; anything else is a
          // conflict and must not touch this device's log/head.
          if (sameAttestationIdentity(committed, e)) {
            return { outcome: 'replay', envelope: committed };
          }
          return {
            outcome: 'reject',
            status: 409,
            code: ErrorCode.GENERATION_CONFLICT,
            message: 'attestationId was already accepted with different content',
            details: {
              attestationId: e.attestationId,
              acceptedDeviceId: committed.deviceId,
              submittedDeviceId: e.deviceId,
              acceptedGeneration: committed.generation,
              acceptedConfigSha256: committed.configSha256,
            },
          };
        }

        const line = `${JSON.stringify(e)}\n`;
        // Device log first (source of truth); the global index second. A crash
        // between the two is healed on restart by reindexing the device record.
        await appendDurable(state.file, line);
        await appendDurable(this.indexFile, line);

        state.generation = e.generation;
        state.configSha256 = e.configSha256;
        state.configSize = e.configSize;
        state.keyId = e.keyId;
        state.attestations.set(e.attestationId, e);
        this.attestations.set(e.attestationId, e);
        return { outcome: 'accept', envelope: e };
      });
    });

    // Keep the chain alive even when this request fails, and free it once settled.
    state.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /** Serialize global-index check-and-commit across all devices. */
  runIndexExclusive(fn) {
    const run = this.indexChain.then(fn);
    this.indexChain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async recoverIndex() {
    let buf;
    try {
      buf = await fs.readFile(this.indexFile);
    } catch {
      return;
    }

    if (buf.length > 0) {
      // Drop a torn trailing record (crash mid-write).
      const lastNl = buf.lastIndexOf(0x0a);
      if (lastNl !== buf.length - 1) {
        buf = buf.subarray(0, lastNl + 1);
        await fs.writeFile(this.indexFile, buf);
      }
    }

    const text = buf.toString('utf8');
    if (!text.trim()) return;

    for (const line of text.split('\n')) {
      if (!line) continue;
      let e;
      try {
        e = JSON.parse(line);
      } catch (err) {
        throw new Error(`Corrupt index ${this.indexFile}: record is not valid JSON (${err.message})`);
      }
      validateRecoveredEnvelope(e, this.indexFile);
      if (this.attestations.has(e.attestationId)) {
        throw new Error(`Corrupt index ${this.indexFile}: duplicate attestationId ${e.attestationId}`);
      }
      this.attestations.set(e.attestationId, e);
    }
  }

  async recoverDeviceFile(state, seenIds) {
    let buf;
    try {
      buf = await fs.readFile(state.file);
    } catch {
      return;
    }

    if (buf.length > 0) {
      // Drop a torn trailing record (crash mid-write) after fsync-less kill.
      const lastNl = buf.lastIndexOf(0x0a);
      if (lastNl !== buf.length - 1) {
        buf = buf.subarray(0, lastNl + 1);
        await fs.writeFile(state.file, buf);
      }
    }

    const text = buf.toString('utf8');
    if (!text.trim()) return;

    let expectedPrev = 0;
    const lines = text.split('\n');
    for (const line of lines) {
      if (!line) continue;
      let e;
      try {
        e = JSON.parse(line);
      } catch (err) {
        throw new Error(`Corrupt log ${state.file}: record is not valid JSON (${err.message})`);
      }
      validateRecoveredEnvelope(e, state.file);
      if (e.previousGeneration !== expectedPrev) {
        throw new Error(
          `Corrupt log ${state.file}: generation ${e.generation} claims predecessor ` +
            `${e.previousGeneration}, expected ${expectedPrev}`,
        );
      }
      if (e.generation <= expectedPrev) {
        throw new Error(`Corrupt log ${state.file}: generation did not advance at ${e.generation}`);
      }
      if (state.attestations.has(e.attestationId)) {
        throw new Error(`Corrupt log ${state.file}: duplicate attestationId ${e.attestationId}`);
      }

      // Cross-check the global index: this number must either be unknown
      // (heal it: a crash between the two appends left the index behind) or
      // map to byte-identical content. A mismatch means the same
      // attestationId was accepted for different content somewhere.
      const indexed = this.attestations.get(e.attestationId);
      if (indexed) {
        if (!sameAttestationIdentity(indexed, e)) {
          throw new Error(
            `Corrupt log ${state.file}: attestationId ${e.attestationId} was already ` +
              `accepted with different content (device ${indexed.deviceId})`,
          );
        }
      } else {
        await appendDurable(this.indexFile, `${line}\n`);
        this.attestations.set(e.attestationId, e);
      }

      state.attestations.set(e.attestationId, e);
      state.generation = e.generation;
      state.configSha256 = e.configSha256;
      state.configSize = e.configSize;
      state.keyId = e.keyId;
      seenIds.add(e.attestationId);
      expectedPrev = e.generation;
    }
  }
}

function stripAction(d) {
  const { action, ...rest } = d;
  return rest;
}

async function appendDurable(file, line) {
  // 'a' is O_APPEND on POSIX; fsync guarantees the record survives a crash
  // before the client is told "accepted".
  let fh;
  try {
    fh = await fs.open(file, 'a');
    await fh.appendFile(line);
    await fh.sync();
  } finally {
    if (fh) await fh.close().catch(() => {});
  }
}

function validateRecoveredEnvelope(e, file) {
  const need = [
    'attestationId',
    'deviceId',
    'keyId',
    'generation',
    'previousGeneration',
    'configSha256',
  ];
  for (const k of need) {
    if (e[k] === undefined) throw new Error(`Corrupt log ${file}: record missing "${k}"`);
  }
  if (!Number.isInteger(e.generation) || e.generation <= 0) {
    throw new Error(`Corrupt log ${file}: bad generation ${e.generation}`);
  }
  if (!Number.isInteger(e.previousGeneration) || e.previousGeneration < 0) {
    throw new Error(`Corrupt log ${file}: bad previousGeneration ${e.previousGeneration}`);
  }
  if (typeof e.configSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(e.configSha256)) {
    throw new Error(`Corrupt log ${file}: bad configSha256`);
  }
  // payloadSha256 was introduced later; tolerate its absence in old records,
  // but never accept a malformed value when present.
  if (e.payloadSha256 !== undefined &&
      (typeof e.payloadSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(e.payloadSha256))) {
    throw new Error(`Corrupt log ${file}: bad payloadSha256`);
  }
}

// deviceId goes into a file name: percent-encode anything not filesystem-safe.
function encodeDeviceFile(deviceId) {
  return `${encodeURIComponent(deviceId)}.log`;
}
function decodeDeviceFile(name) {
  return decodeURIComponent(name.slice(0, -4));
}

export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// Kept for tests/tools that want to force fsync behavior checks.
export const _internals = { appendDurable, fssync };
