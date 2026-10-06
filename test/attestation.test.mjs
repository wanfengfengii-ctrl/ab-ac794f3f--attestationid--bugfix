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
  return { dir, store, service, priv1, priv2, poolPriv: privateKeyFromSeed(pool.seed) };
}

function config(seed) {
  const bytes = Buffer.from(seed, 'utf8');
  return { bytes, sha: sha256Hex(bytes) };
}

function body(priv, keyId, payload, attestationId = `att-${Math.random().toString(36).slice(2)}`) {
  const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
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
