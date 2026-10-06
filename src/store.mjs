import fs from 'node:fs/promises';
import fssync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Durable, append-only store of accepted attestations.
 *
 * Per-device log file: <dataDir>/configs/<deviceId>.log
 * One JSON envelope per line, newest last:
 *   {"attestationId","deviceId","keyId","generation","previousGeneration",
 *    "configSha256","payloadSha256","configSize","acceptedAt"}
 *
 * Durability: every accepted write is flushed (fsync) before the API replies.
 * Restart: logs are replayed, the chain is revalidated, and the in-memory
 * "head" is rebuilt so GET .../head always reports the single accepted tip.
 *
 * Idempotency scope: attestationId is a GLOBALLY unique acceptance number.
 * The global id -> envelope index spans every device log and is rebuilt from
 * disk on restart, so the same number can never denote two different devices
 * or payloads, including across restarts.
 *
 * Concurrency: accept() runs every check-then-append decision on one global
 * commit chain. This is strictly stronger than per-device serialization: the
 * global attestationId lookup and the durable append happen in one atomic
 * critical section, so concurrent submissions carrying the same
 * attestationId (even for different devices) have exactly one deterministic
 * winner and the other gets a conflict without touching any device's state.
 */
export class AttestationStore {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.configsDir = path.join(dataDir, 'configs');
    // deviceId -> {
    //   generation: number, configSha256: string, configSize: number,
    //   keyId: string|null, file: string
    // }
    this.devices = new Map();
    // Global index: attestationId -> accepted envelope, across all devices.
    this.attestations = new Map();
    // Single serialization point for all check-then-append decisions.
    this.chain = Promise.resolve();
  }

  async init() {
    await fs.mkdir(this.configsDir, { recursive: true });
    const names = await fs.readdir(this.configsDir).catch(() => []);
    for (const name of names) {
      if (!name.endsWith('.log')) continue;
      const deviceId = decodeDeviceFile(name);
      const file = path.join(this.configsDir, name);
      const state = {
        generation: 0,
        configSha256: null,
        configSize: 0,
        keyId: null,
        file,
      };
      await recoverFile(state, this.attestations);
      this.devices.set(deviceId, state);
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

  /**
   * Look up a previously accepted envelope by attestationId. The id is global
   * (not per device), so no deviceId argument is needed.
   */
  findAttestation(attestationId) {
    return this.attestations.get(attestationId) ?? null;
  }

  /**
   * Validate-then-append inside one global critical section.
   * decision(existingHead) must return either:
   *   { action: 'accept', envelope: {...record fields} }
   *   { action: 'reject', status, code, message, details? }
   *   { action: 'replay', envelope: previousEnvelope }  -> returned as accepted(duplicate)
   * Rejections never touch any log or in-memory state.
   *
   * Serializing on a single chain (rather than one chain per device) makes the
   * global attestationId uniqueness check and the durable append atomic even
   * when the racing submissions target different devices.
   */
  accept(deviceId, decisionFn) {
    let state = this.devices.get(deviceId);
    if (!state) {
      state = {
        generation: 0,
        configSha256: null,
        configSize: 0,
        keyId: null,
        file: path.join(this.configsDir, encodeDeviceFile(deviceId)),
      };
      this.devices.set(deviceId, state);
    }

    const run = this.chain.then(async () => {
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

      const e = decision.envelope;
      const line = `${JSON.stringify(e)}\n`;
      await appendDurable(state.file, line);

      state.generation = e.generation;
      state.configSha256 = e.configSha256;
      state.configSize = e.configSize;
      state.keyId = e.keyId;
      this.attestations.set(e.attestationId, e);
      return { outcome: 'accept', envelope: e };
    });

    // Keep the chain alive even when this request fails, and free it once settled.
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
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

async function recoverFile(state, globalAttestations) {
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
    if (globalAttestations.has(e.attestationId)) {
      const owner = globalAttestations.get(e.attestationId);
      throw new Error(
        `Corrupt store: attestationId ${e.attestationId} is accepted for both ` +
          `"${owner.deviceId}" and "${e.deviceId ?? state.file}"`,
      );
    }
    globalAttestations.set(e.attestationId, e);
    state.generation = e.generation;
    state.configSha256 = e.configSha256;
    state.configSize = e.configSize;
    state.keyId = e.keyId;
    expectedPrev = e.generation;
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
    'payloadSha256',
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
  if (typeof e.payloadSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(e.payloadSha256)) {
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
