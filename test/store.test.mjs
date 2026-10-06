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
