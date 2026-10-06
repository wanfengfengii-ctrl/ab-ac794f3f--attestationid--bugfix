import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DeviceRegistry } from '../src/registry.mjs';
import { AttestationStore } from '../src/store.mjs';
import { createAttestationService } from '../src/attestation.mjs';
import { generateDeviceKey, privateKeyFromSeed, signPayload, sha256Hex } from '../tools/signing.mjs';

async function harness() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-svc-'));
  const d1 = generateDeviceKey();
  const d2 = generateDeviceKey();
  const pool = generateDeviceKey();
  const registry = DeviceRegistry.fromManifest({
    keys: {
      'key-1': d1.publicRaw.toString('base64'),
      'key-2': d2.publicRaw.toString('base64'),
      'key-pool': pool.publicRaw.toString('base64'),
    },
    devices: {
      dev1: { keyId: 'key-1', publicKey: d1.publicRaw.toString('base64') },
      dev2: { keyId: 'key-2', publicKey: d2.publicRaw.toString('base64') },
    },
  });
  const store = new AttestationStore(path.join(dir, 'data'));
  await store.init();
  const service = createAttestationService({ store, registry, maxPayloadBytes: 64 * 1024 });
  const priv1 = privateKeyFromSeed(d1.seed);
  const priv2 = privateKeyFromSeed(d2.seed);
  return { dir, registry, store, service, priv1, priv2, poolPriv: privateKeyFromSeed(pool.seed) };
}

function config(seed) {
  const bytes = Buffer.from(seed, 'utf8');
  return { bytes, sha: sha256Hex(bytes) };
}

function body(priv, keyId, payload, attestationId = `att-${Math.random().toString(36).slice(2)}`) {
  const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
  return bodyBytes(priv, keyId, payloadBytes, attestationId);
}

function bodyBytes(priv, keyId, payloadBytes, attestationId) {
  return {
    attestationId,
    keyId,
    payloadBase64: payloadBytes.toString('base64'),
    signatureBase64: signPayload(priv, payloadBytes),
  };
}

function payload(deviceId, generation, previousGeneration, sha) {
  return { deviceId, generation, previousGeneration, configSha256: sha };
}

test('happy path: root, advance, replay', async () => {
  const { service, store, priv1 } = await harness();
  const c1 = config('cfg-1');
  const c2 = config('cfg-2');

  const r1 = await service.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha), 'att-1'));
  assert.equal(r1.replayed, false);
  assert.equal(r1.head.generation, 1);
  assert.equal(r1.head.configSha256, c1.sha);

  // Exact retry, even re-signed bytes (same JSON) -> original result.
  const r1b = await service.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha), 'att-1'));
  assert.equal(r1b.replayed, true);
  assert.equal(r1b.accepted.attestationId, 'att-1');
  assert.equal(service.head('dev1').generation, 1);

  const r2 = await service.submit(body(priv1, 'key-1', payload('dev1', 2, 1, c2.sha), 'att-2'));
  assert.equal(r2.head.generation, 2);
});

test('first submission must root at predecessor zero', async () => {
  const { service, store, priv1 } = await harness();
  const c = config('x');
  await assert.rejects(
    () => service.submit(body(priv1, 'key-1', payload('dev1', 3, 2, c.sha))),
    (err) => err.status === 409 && err.code === 'PREDECESSOR_MISMATCH',
  );
  assert.equal(store.head('dev1'), null);
});

test('same attestation id with different content conflicts and never mutates state', async () => {
  const { service, store, priv1 } = await harness();
  const c1 = config('cfg-1');
  const c1b = config('cfg-1-prime');
  await service.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha), 'att-1'));

  await assert.rejects(
    () => service.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1b.sha), 'att-1')),
    (err) => err.status === 409 && err.code === 'GENERATION_CONFLICT',
  );
  assert.equal(service.head('dev1').configSha256, c1.sha);
  assert.equal(service.head('dev1').generation, 1);
});

test('same id reused by a different device (different key/config) is 409 and creates no head', async () => {
  const { service, store, priv1, priv2 } = await harness();
  const c1 = config('cfg-dev1');
  const c2 = config('cfg-dev2');

  const r1 = await service.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha), 'shared-att'));
  assert.equal(r1.replayed, false);
  assert.equal(r1.head.deviceId, 'dev1');

  await assert.rejects(
    () => service.submit(body(priv2, 'key-2', payload('dev2', 1, 0, c2.sha), 'shared-att')),
    (err) => {
      if (err.status !== 409 || err.code !== 'GENERATION_CONFLICT') return false;
      assert.equal(err.details.acceptedDeviceId, 'dev1');
      assert.equal(err.details.submittedDeviceId, 'dev2');
      return true;
    },
  );

  // The conflict neither created dev2's head nor moved dev1.
  assert.equal(store.head('dev2'), null);
  assert.equal(service.head('dev1').generation, 1);
  assert.equal(service.head('dev1').configSha256, c1.sha);

  // A fresh, unused id for dev2 is accepted normally.
  const r2 = await service.submit(body(priv2, 'key-2', payload('dev2', 1, 0, c2.sha), 'att-dev2'));
  assert.equal(r2.replayed, false);
  assert.equal(r2.head.deviceId, 'dev2');
  assert.equal(r2.head.generation, 1);
});

test('same-device exact byte-for-byte retry replays the first acceptance', async () => {
  const { service, priv1 } = await harness();
  const c1 = config('cfg-1');
  const bytes = Buffer.from(JSON.stringify(payload('dev1', 1, 0, c1.sha)), 'utf8');

  const r1 = await service.submit(bodyBytes(priv1, 'key-1', bytes, 'exact-1'));
  assert.equal(r1.replayed, false);

  // Re-sign the identical bytes (new signature) but keep the exact payload.
  const r2 = await service.submit(bodyBytes(priv1, 'key-1', Buffer.from(bytes), 'exact-1'));
  assert.equal(r2.replayed, true);
  assert.equal(r2.accepted.attestationId, 'exact-1');
  assert.equal(service.head('dev1').generation, 1);
  assert.equal(service.head('dev1').configSha256, c1.sha);
});

test('same id with identical logical fields but changed signed bytes (extra field) is 409', async () => {
  const { service, store, priv1 } = await harness();
  const c1 = config('cfg-1');
  const base = { deviceId: 'dev1', generation: 1, previousGeneration: 0, configSha256: c1.sha };

  await service.submit(bodyBytes(priv1, 'key-1', Buffer.from(JSON.stringify(base), 'utf8'), 'bytes-1'));

  // keyId/generation/previousGeneration/configSha256 unchanged, but an extra
  // signed field (and thus different exact signed JSON) must conflict.
  const altered = { ...base, nonce: 'different-bytes' };
  await assert.rejects(
    () => service.submit(bodyBytes(priv1, 'key-1', Buffer.from(JSON.stringify(altered), 'utf8'), 'bytes-1')),
    (err) => err.status === 409 && err.code === 'GENERATION_CONFLICT',
  );

  // Same via pure byte re-encoding (field order / whitespace), still signed.
  const reordered = Buffer.from(
    JSON.stringify(Object.fromEntries(Object.entries(base).reverse())),
    'utf8',
  );
  assert.notDeepEqual(reordered.toString(), JSON.stringify(base));
  await assert.rejects(
    () => service.submit(bodyBytes(priv1, 'key-1', reordered, 'bytes-1')),
    (err) => err.status === 409 && err.code === 'GENERATION_CONFLICT',
  );

  assert.equal(service.head('dev1').generation, 1);
  assert.equal(service.head('dev1').configSha256, c1.sha);
  void store;
});

test('concurrent cross-device reuse of one id: exactly one deterministic winner', async () => {
  const { service, store, priv1, priv2 } = await harness();
  const c1 = config('cfg-dev1');
  const c2 = config('cfg-dev2');

  const results = await Promise.allSettled([
    service.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha), 'race-att')),
    service.submit(body(priv2, 'key-2', payload('dev2', 1, 0, c2.sha), 'race-att')),
  ]);
  const fulfilled = results.filter((r) => r.status === 'fulfilled');
  const rejected = results.filter((r) => r.status === 'rejected');

  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.status, 409);
  assert.equal(rejected[0].reason.code, 'GENERATION_CONFLICT');

  const winner = fulfilled[0].value.accepted.deviceId;
  assert.ok(winner === 'dev1' || winner === 'dev2');
  const loser = winner === 'dev1' ? 'dev2' : 'dev1';

  // Loser has no head; winner's head is its own config; the id names one owner.
  assert.equal(store.head(loser), null);
  assert.equal(store.head(winner).generation, 1);
  assert.equal(store.findAttestation('race-att').deviceId, winner);
});

test('global id dedup still holds after a service/store restart (durable index)', async () => {
  const { dir, registry, priv1, priv2 } = await harness();
  const c1 = config('cfg-dev1');
  const c2 = config('cfg-dev2');

  const store1 = new AttestationStore(path.join(dir, 'data-restart'));
  await store1.init();
  const service1 = createAttestationService({ store: store1, registry, maxPayloadBytes: 64 * 1024 });
  await service1.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha), 'restart-att'));

  // New process: fresh in-memory index rebuilt from the on-disk logs.
  const store2 = new AttestationStore(path.join(dir, 'data-restart'));
  await store2.init();
  const service2 = createAttestationService({ store: store2, registry, maxPayloadBytes: 64 * 1024 });

  // Exact replay of the original still returns the original result.
  const replay = await service2.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha), 'restart-att'));
  assert.equal(replay.replayed, true);

  // Cross-device reuse of the same id is rejected after restart, too.
  await assert.rejects(
    () => service2.submit(body(priv2, 'key-2', payload('dev2', 1, 0, c2.sha), 'restart-att')),
    (err) => err.status === 409 && err.code === 'GENERATION_CONFLICT',
  );
  assert.equal(store2.head('dev2'), null);
  assert.equal(store2.head('dev1').generation, 1);
  assert.equal(store2.head('dev1').configSha256, c1.sha);
});

test('stale predecessor conflicts', async () => {
  const { service, store, priv1 } = await harness();
  const c1 = config('cfg-1');
  const c9 = config('cfg-9');
  await service.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha)));
  await assert.rejects(
    () => service.submit(body(priv1, 'key-1', payload('dev1', 9, 0, c9.sha))),
    (err) => err.status === 409 && err.code === 'PREDECESSOR_MISMATCH',
  );
  assert.equal(service.head('dev1').generation, 1);
});

test('rollback to older generation conflicts', async () => {
  const { service, store, priv1 } = await harness();
  const c1 = config('cfg-1');
  const c2 = config('cfg-2');
  const cOld = config('cfg-old');
  await service.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha)));
  await service.submit(body(priv1, 'key-1', payload('dev1', 2, 1, c2.sha)));
  await assert.rejects(
    () => service.submit(body(priv1, 'key-1', payload('dev1', 1, 2, cOld.sha))),
    (err) => err.status === 409 && err.code === 'GENERATION_NOT_ADVANCED',
  );
});

test('unknown key id is rejected with UNKNOWN_KEY and state is untouched', async () => {
  const { service, store, priv1 } = await harness();
  const c = config('cfg-1');
  await assert.rejects(
    () => service.submit(body(priv1, 'ghost-key', payload('dev1', 1, 0, c.sha))),
    (err) => err.status === 401 && err.code === 'UNKNOWN_KEY',
  );
  assert.equal(store.head('dev1'), null);
});

test('a signature from another device key is rejected', async () => {
  const { service, store, priv2 } = await harness();
  const c = config('cfg-1');
  await assert.rejects(
    () => service.submit(body(priv2, 'key-2', payload('dev1', 1, 0, c.sha))),
    (err) => err.status === 403 && err.code === 'KEY_DEVICE_MISMATCH',
  );
  assert.equal(store.head('dev1'), null);
});

test('tampered signature is rejected with INVALID_SIGNATURE and state is untouched', async () => {
  const { service, store, priv1 } = await harness();
  const c1 = config('cfg-1');
  const b = body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha));
  const sig = Buffer.from(b.signatureBase64, 'base64');
  sig[sig.length - 1] ^= 0x01;
  b.signatureBase64 = sig.toString('base64');
  await assert.rejects(
    () => service.submit(b),
    (err) => err.status === 401 && err.code === 'INVALID_SIGNATURE',
  );
  assert.equal(store.head('dev1'), null);
});

test('signature must cover the exact payload bytes (payload mutation fails)', async () => {
  const { service, store, priv1 } = await harness();
  const c1 = config('cfg-1');
  const c2 = config('cfg-2');
  const b = body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha));
  // Re-encode a different payload but keep the original signature.
  b.payloadBase64 = Buffer.from(JSON.stringify(payload('dev1', 1, 0, c2.sha)), 'utf8').toString('base64');
  await assert.rejects(
    () => service.submit(b),
    (err) => err.status === 401 && err.code === 'INVALID_SIGNATURE',
  );
});

test('concurrent conflicting submissions never fork: exactly one wins', async () => {
  const { service, store, priv1 } = await harness();
  const c1 = config('cfg-1');
  const ca = config('branch-a');
  const cb = config('branch-b');
  await service.submit(body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha)));

  const results = await Promise.allSettled([
    service.submit(body(priv1, 'key-1', payload('dev1', 2, 1, ca.sha))),
    service.submit(body(priv1, 'key-1', payload('dev1', 2, 1, cb.sha))),
  ]);
  const fulfilled = results.filter((r) => r.status === 'fulfilled');
  const rejected = results.filter((r) => r.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.status, 409);
  assert.ok(['GENERATION_CONFLICT', 'PREDECESSOR_MISMATCH'].includes(rejected[0].reason.code));
  assert.equal(service.head('dev1').generation, 2);
  assert.ok([ca.sha, cb.sha].includes(service.head('dev1').configSha256));
});

test('concurrent duplicate (same id, same content) both succeed as idempotent replays', async () => {
  const { service, store, priv1 } = await harness();
  const c1 = config('cfg-1');
  const mk = () => body(priv1, 'key-1', payload('dev1', 1, 0, c1.sha), 'dup-1');
  const [a, b] = await Promise.all([service.submit(mk()), service.submit(mk())]);
  const heads = [a.head.generation, b.head.generation];
  assert.deepEqual(heads, [1, 1]);
  // At least one reports replay and the head was written exactly once.
  assert.ok(a.replayed || b.replayed);
});

test('an undeclared pool key may onboard a new device but cannot attest a bound device', async () => {
  const { service, store, priv1, poolPriv } = await harness();
  const c = config('cfg-onboard');
  const r = await service.submit(body(poolPriv, 'key-pool', payload('new-dev', 1, 0, c.sha)));
  assert.equal(r.head.deviceId, 'new-dev');

  const c2 = config('cfg-x');
  await assert.rejects(
    () => service.submit(body(poolPriv, 'key-pool', payload('dev1', 1, 0, c2.sha))),
    (err) => err.status === 403 && err.code === 'KEY_DEVICE_MISMATCH',
  );
  void priv1;
});

test('head of unknown device throws DEVICE_NOT_FOUND', async () => {
  const { service } = await harness();
  assert.throws(() => service.head('ghost'), (err) => err.status === 404 && err.code === 'DEVICE_NOT_FOUND');
});
