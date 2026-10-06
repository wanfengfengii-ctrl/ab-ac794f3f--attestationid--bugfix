import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AttestationStore } from '../src/store.mjs';

function tmpStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-store-'));
  const store = new AttestationStore(dir);
  return { dir, store };
}

const env = (attestationId, gen, prev, sha = 'a'.repeat(64)) => ({
  attestationId,
  keyId: 'k1',
  deviceId: 'dev',
  generation: gen,
  previousGeneration: prev,
  configSha256: sha,
  payloadSha256: 'c'.repeat(64),
  configSize: 10,
  acceptedAt: new Date().toISOString(),
});

test('store accepts, reports head, and replays by attestationId', async () => {
  const { store } = tmpStore();
  await store.init();
  assert.equal(store.head('dev'), null);

  const r1 = await store.accept('dev', () => ({ action: 'accept', envelope: env('a1', 1, 0) }));
  assert.equal(r1.outcome, 'accept');
  assert.deepEqual(store.head('dev').generation, 1);

  const r2 = await store.accept('dev', (head) => {
    assert.equal(head.generation, 1);
    return { action: 'replay', envelope: env('a1', 1, 0) };
  });
  assert.equal(r2.outcome, 'replay');
  assert.equal(store.head('dev').generation, 1);
});

test('store rejects never mutate state', async () => {
  const { store } = tmpStore();
  await store.init();
  await store.accept('dev', () => ({ action: 'accept', envelope: env('a1', 1, 0) }));
  const r = await store.accept('dev', () => ({
    action: 'reject', status: 409, code: 'X', message: 'nope',
  }));
  assert.equal(r.outcome, 'reject');
  assert.equal(store.head('dev').generation, 1);
});

test('store recovers head and attestation index from disk on restart', async () => {
  const { dir, store } = tmpStore();
  await store.init();
  await store.accept('dev', () => ({ action: 'accept', envelope: env('a1', 1, 0) }));
  await store.accept('dev', () => ({ action: 'accept', envelope: env('a2', 2, 1, 'b'.repeat(64)) }));

  const reopened = new AttestationStore(dir);
  await reopened.init();
  assert.equal(reopened.head('dev').generation, 2);
  assert.equal(reopened.head('dev').configSha256, 'b'.repeat(64));
  assert.ok(reopened.findAttestation('dev', 'a1'));
  assert.ok(reopened.findAttestation('dev', 'a2'));
});

test('store truncates a torn trailing record after a crash mid-write', async () => {
  const { dir, store } = tmpStore();
  await store.init();
  await store.accept('dev', () => ({ action: 'accept', envelope: env('a1', 1, 0) }));

  // Simulate a torn append: partial JSON, no terminating newline.
  fs.appendFileSync(path.join(dir, 'configs', 'dev.log'), '{"attestationId":"a2","generat');

  const reopened = new AttestationStore(dir);
  await reopened.init();
  assert.equal(reopened.head('dev').generation, 1);

  // Log continues to append cleanly after truncation.
  await reopened.accept('dev', () => ({ action: 'accept', envelope: env('a2', 2, 1, 'b'.repeat(64)) }));
  assert.equal(reopened.head('dev').generation, 2);
});

test('store refuses to recover a log whose chain is broken', async () => {
  const { dir } = tmpStore();
  fs.mkdirSync(path.join(dir, 'configs'), { recursive: true });
  const broken = { ...env('a1', 1, 0), previousGeneration: 5 };
  fs.writeFileSync(path.join(dir, 'configs', 'dev.log'), `${JSON.stringify(broken)}\n`);
  const reopened = new AttestationStore(dir);
  await assert.rejects(() => reopened.init(), /expected 0|Corrupt log/);
});

test('store serializes concurrent decisions per device (no fork)', async () => {
  const { store } = tmpStore();
  await store.init();
  await store.accept('dev', () => ({ action: 'accept', envelope: env('a1', 1, 0) }));

  // Both decisions see head=1; whichever appends first becomes gen 2; the
  // second decision function observes the updated head=2 while still in the queue.
  const outcomes = await Promise.all([
    store.accept('dev', (head) =>
      head.generation === 1
        ? { action: 'accept', envelope: env('a2', 2, 1, 'c'.repeat(64)) }
        : { action: 'reject', status: 409, code: 'GENERATION_CONFLICT', message: 'lost' }),
    store.accept('dev', (head) =>
      head.generation === 1
        ? { action: 'accept', envelope: env('a2b', 2, 1, 'd'.repeat(64)) }
        : { action: 'reject', status: 409, code: 'GENERATION_CONFLICT', message: 'lost' }),
  ]);
  const accepted = outcomes.filter((o) => o.outcome === 'accept');
  const rejected = outcomes.filter((o) => o.outcome === 'reject');
  assert.equal(accepted.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(store.head('dev').generation, 2);
});

test('store isolates chains for different devices', async () => {
  const { store } = tmpStore();
  await store.init();
  await store.accept('devA', () => ({ action: 'accept', envelope: env('a1', 1, 0) }));
  await store.accept('devB', () => ({ action: 'accept', envelope: env('b1', 1, 0) }));
  assert.equal(store.head('devA').generation, 1);
  assert.equal(store.head('devB').generation, 1);
  assert.equal(store.findAttestation('devA', 'b1'), null);
});

const envFor = (deviceId, attestationId, gen, prev, sha = 'a'.repeat(64), extra = {}) => ({
  ...env(attestationId, gen, prev, sha),
  deviceId,
  ...extra,
});

test('global index: the same attestationId is accepted only once across devices', async () => {
  const { store, dir } = tmpStore();
  await store.init();
  const r1 = await store.accept('devA', () => ({ action: 'accept', envelope: envFor('devA', 'shared', 1, 0) }));
  assert.equal(r1.outcome, 'accept');

  // A different device claiming the same number: rejected at the global
  // check-and-commit, with no write to devB's log or head.
  const r2 = await store.accept('devB', () => ({
    action: 'accept',
    envelope: envFor('devB', 'shared', 1, 0, 'b'.repeat(64)),
  }));
  assert.equal(r2.outcome, 'reject');
  assert.equal(r2.code, 'GENERATION_CONFLICT');
  assert.equal(store.head('devB'), null);
  assert.equal(store.findAcceptedAttestation('shared').deviceId, 'devA');

  // Exactly one global index line and no devB log on disk.
  const idx = fs.readFileSync(path.join(dir, 'attestations.log'), 'utf8').trim().split('\n');
  assert.equal(idx.length, 1);
  assert.equal(JSON.parse(idx[0]).deviceId, 'devA');
  assert.ok(!fs.existsSync(path.join(dir, 'configs', 'devB.log')));
});

test('global index: concurrent cross-device submissions of one id resolve to one acceptance', async () => {
  const { store } = tmpStore();
  await store.init();
  const outcomes = await Promise.all([
    store.accept('devA', () => ({ action: 'accept', envelope: envFor('devA', 'race', 1, 0, 'a'.repeat(64)) })),
    store.accept('devB', () => ({ action: 'accept', envelope: envFor('devB', 'race', 1, 0, 'b'.repeat(64)) })),
  ]);
  const accepted = outcomes.filter((o) => o.outcome === 'accept');
  const rejected = outcomes.filter((o) => o.outcome === 'reject');
  assert.equal(accepted.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].code, 'GENERATION_CONFLICT');
  const winner = accepted[0].envelope.deviceId;
  assert.equal(store.findAcceptedAttestation('race').deviceId, winner);
  assert.equal(store.head(winner).generation, 1);
  assert.equal(store.head(winner === 'devA' ? 'devB' : 'devA'), null);
});

test('global index: same id with identical identity still replays on the winning device', async () => {
  const { store } = tmpStore();
  await store.init();
  const e = envFor('devA', 'dup', 1, 0);
  await store.accept('devA', () => ({ action: 'accept', envelope: e }));
  const r = await store.accept('devA', () => ({ action: 'replay', envelope: e }));
  assert.equal(r.outcome, 'replay');
  assert.equal(store.head('devA').generation, 1);
});

test('global index survives restart and keeps rejecting other devices', async () => {
  const { dir } = tmpStore();
  let store = new AttestationStore(dir);
  await store.init();
  await store.accept('devA', () => ({ action: 'accept', envelope: envFor('devA', 'shared', 1, 0) }));

  const reopened = new AttestationStore(dir);
  await reopened.init();
  assert.equal(reopened.findAcceptedAttestation('shared').deviceId, 'devA');
  const r = await reopened.accept('devB', () => ({
    action: 'accept',
    envelope: envFor('devB', 'shared', 1, 0, 'b'.repeat(64)),
  }));
  assert.equal(r.outcome, 'reject');
  assert.equal(r.code, 'GENERATION_CONFLICT');
  assert.equal(reopened.head('devB'), null);
});

test('recovery heals a device record missing from the global index (crash between appends)', async () => {
  const { dir } = tmpStore();
  fs.mkdirSync(path.join(dir, 'configs'), { recursive: true });
  // Device log exists, global index does not.
  fs.writeFileSync(path.join(dir, 'configs', 'devA.log'), `${JSON.stringify(envFor('devA', 'a1', 1, 0))}\n`);

  const reopened = new AttestationStore(dir);
  await reopened.init();
  assert.equal(reopened.head('devA').generation, 1);
  assert.equal(reopened.findAcceptedAttestation('a1').deviceId, 'devA');
  // Index was rebuilt from the device record.
  const idx = fs.readFileSync(path.join(dir, 'attestations.log'), 'utf8').trim();
  assert.equal(JSON.parse(idx).attestationId, 'a1');
});

test('recovery refuses logs where one id was accepted with different content on two devices', async () => {
  const { dir } = tmpStore();
  fs.mkdirSync(path.join(dir, 'configs'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'configs', 'devA.log'), `${JSON.stringify(envFor('devA', 'shared', 1, 0))}\n`);
  fs.writeFileSync(path.join(dir, 'configs', 'devB.log'),
    `${JSON.stringify(envFor('devB', 'shared', 1, 0, 'b'.repeat(64)))}\n`);
  const reopened = new AttestationStore(dir);
  await assert.rejects(() => reopened.init(), /different content|Corrupt/);
});

test('recovery tolerates legacy records without payloadSha256 (existing data volumes)', async () => {
  const { dir } = tmpStore();
  fs.mkdirSync(path.join(dir, 'configs'), { recursive: true });
  const legacy = envFor('devA', 'a1', 1, 0);
  delete legacy.payloadSha256;
  fs.writeFileSync(path.join(dir, 'configs', 'devA.log'), `${JSON.stringify(legacy)}\n`);

  const store = new AttestationStore(dir);
  await store.init();
  assert.equal(store.head('devA').generation, 1);
  // Healed into the global index; byte comparison is skipped for the legacy row.
  assert.equal(store.findAcceptedAttestation('a1').deviceId, 'devA');

  // Same id reused by another device still conflicts after the upgrade.
  const r = await store.accept('devB', () => ({
    action: 'accept',
    envelope: envFor('devB', 'a1', 1, 0, 'b'.repeat(64)),
  }));
  assert.equal(r.outcome, 'reject');
  assert.equal(r.code, 'GENERATION_CONFLICT');
  assert.equal(store.head('devB'), null);
});
