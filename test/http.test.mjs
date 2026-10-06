import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DeviceRegistry } from '../src/registry.mjs';
import { AttestationStore } from '../src/store.mjs';
import { createAttestationService } from '../src/attestation.mjs';
import { createApp } from '../src/app.mjs';
import { generateDeviceKey, privateKeyFromSeed, signPayload, sha256Hex } from '../tools/signing.mjs';

async function start() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-http-'));
  const d1 = generateDeviceKey();
  const registry = DeviceRegistry.fromManifest({
    keys: { 'key-1': d1.publicRaw.toString('base64') },
    devices: { dev1: { keyId: 'key-1', publicKey: d1.publicRaw.toString('base64') } },
  });
  const store = new AttestationStore(path.join(dir, 'data'));
  await store.init();
  const service = createAttestationService({ store, registry, maxPayloadBytes: 64 * 1024 });
  const server = createServer(createApp(service));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;
  const priv = privateKeyFromSeed(d1.seed);

  const stop = () => new Promise((resolve) => server.close(resolve));
  return { base, priv, stop };
}

function submitBody(priv, payloadObj, attestationId = 'att-1') {
  const bytes = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  return {
    attestationId,
    keyId: 'key-1',
    payloadBase64: bytes.toString('base64'),
    signatureBase64: signPayload(priv, bytes),
  };
}

test('GET /health returns ok JSON', async () => {
  const { base, stop } = await start();
  try {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /application\/json/);
    const j = await res.json();
    assert.equal(j.status, 'ok');
  } finally {
    await stop();
  }
});

test('/healthz alias works too', async () => {
  const { base, stop } = await start();
  try {
    const res = await fetch(`${base}/healthz`);
    assert.equal(res.status, 200);
  } finally {
    await stop();
  }
});

test('unknown route -> 404 ROUTE_NOT_FOUND', async () => {
  const { base, stop } = await start();
  try {
    const res = await fetch(`${base}/nope`);
    const j = await res.json();
    assert.equal(res.status, 404);
    assert.equal(j.error.code, 'ROUTE_NOT_FOUND');
  } finally {
    await stop();
  }
});

test('full HTTP flow: accept -> head -> stable error codes', async () => {
  const { base, priv, stop } = await start();
  try {
    const cfg = Buffer.from('{}', 'utf8');
    const sha = sha256Hex(cfg);

    const res = await fetch(`${base}/api/attestations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(submitBody(priv, {
        deviceId: 'dev1', generation: 1, previousGeneration: 0, configSha256: sha,
      })),
    });
    assert.equal(res.status, 201);
    const accepted = await res.json();
    assert.equal(accepted.head.generation, 1);

    const head = await fetch(`${base}/api/devices/dev1/head`);
    assert.equal(head.status, 200);
    assert.deepEqual((await head.json()).configSha256, sha);

    const bad = await fetch(`${base}/api/attestations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ attestationId: 'x', keyId: 'nope', payloadBase64: '', signatureBase64: '' }),
    });
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error.code, 'INVALID_REQUEST');
  } finally {
    await stop();
  }
});

test('device id in path is URI decoded', async () => {
  const { base, stop } = await start();
  try {
    const res = await fetch(`${base}/api/devices/${encodeURIComponent('a b/c')}/head`);
    // space and slash are encoded; unknown either way -> 404 stable code
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error.code, 'DEVICE_NOT_FOUND');
  } finally {
    await stop();
  }
});
