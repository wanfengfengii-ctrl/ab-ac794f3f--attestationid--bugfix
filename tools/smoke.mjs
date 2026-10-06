#!/usr/bin/env node
// End-to-end signature-acceptance smoke against a live HTTP server.
//
// Modes:
//   1. Self-contained (default): generates ephemeral keys in a temp dir,
//      spawns src/server.mjs on an ephemeral port, runs the full scenario
//      including a hard restart to prove durable head recovery, then exits.
//   2. Remote: BASE_URL=http://host:port SMOKE_KEYS_FILE=... node tools/smoke.mjs
//      Runs against an already running server (restart/persistence is skipped).
//
// Exit code is non-zero if any assertion fails.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { startServer } from './harness.mjs';
import {
  publicKeyFromRaw,
  privateKeyFromSeed,
  signPayload,
  sha256Hex,
  randomId,
  generateDeviceKey,
} from './signing.mjs';

const DEVICE = 'SMOKE-SAT-01';
const OTHER_DEVICE = 'SMOKE-SAT-02';
const KEY_ID = 'smoke-sat-01-ed25519-1';
const OTHER_KEY_ID = 'smoke-sat-02-ed25519-1';

let failures = 0;
const checks = [];
function check(name, cond, detail = '') {
  checks.push({ name, ok: !!cond, detail });
  if (!cond) failures += 1;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail && !cond ? ` -- ${detail}` : ''}`);
}

function makeConfig(seedText) {
  const bytes = Buffer.from(seedText, 'utf8');
  return { bytes, sha: sha256Hex(bytes) };
}

function loadKeys(keysFile) {
  const fx = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
  const d1 = fx.devices[DEVICE];
  const d2 = fx.devices[OTHER_DEVICE];
  return {
    [DEVICE]: { keyId: d1.keyId, priv: privateKeyFromSeed(Buffer.from(d1.seedBase64, 'base64')) },
    [OTHER_DEVICE]: { keyId: d2.keyId, priv: privateKeyFromSeed(Buffer.from(d2.seedBase64, 'base64')) },
  };
}

function envelope({ keyId, payload, priv, attestationId }) {
  const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
  return {
    attestationId: attestationId ?? randomId('att'),
    keyId,
    payloadBase64: payloadBytes.toString('base64'),
    signatureBase64: signPayload(priv, payloadBytes),
  };
}

async function api(baseUrl, method, pathname, body) {
  const res = await fetch(new URL(pathname, baseUrl), {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* some error paths */
  }
  return { status: res.status, json };
}

async function scenario(baseUrl, keys) {
  const mine = keys[DEVICE];
  const other = keys[OTHER_DEVICE];
  const cfg1 = makeConfig(JSON.stringify({ name: 'payload-config', version: 1, txPower: 12 }));
  const cfg1b = makeConfig(JSON.stringify({ name: 'payload-config', version: 1, txPower: 13 }));
  const cfg2 = makeConfig(JSON.stringify({ name: 'payload-config', version: 2, txPower: 12 }));
  // Final DEVICE head generation, returned for restart assertions (the
  // cross-device race may or may not advance it).
  let finalDeviceGeneration = 4;
  let finalOtherGeneration = 1;

  // --- health ---
  {
    const r = await api(baseUrl, 'GET', '/health');
    check('health returns 200 ok', r.status === 200 && r.json?.status === 'ok', JSON.stringify(r.json));
  }

  // --- first acceptance: gen 1, predecessor 0 ---
  const firstPayload = {
    deviceId: DEVICE,
    generation: 1,
    previousGeneration: 0,
    configSha256: cfg1.sha,
  };
  const firstId = randomId('att');
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv, payload: firstPayload, attestationId: firstId,
    }));
    check('first attestation accepted (201)', r.status === 201, `status=${r.status} body=${JSON.stringify(r.json)}`);
    check('response head is generation 1', r.json?.head?.generation === 1 && r.json?.head?.configSha256 === cfg1.sha);
  }

  // --- head ---
  {
    const r = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(DEVICE)}/head`);
    check('head reports unique accepted generation 1 + sha',
      r.status === 200 && r.json?.generation === 1 && r.json?.configSha256 === cfg1.sha,
      JSON.stringify(r.json));
  }
  {
    const r = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(OTHER_DEVICE)}/head`);
    check('unknown device head -> 404 DEVICE_NOT_FOUND', r.status === 404 && r.json?.error?.code === 'DEVICE_NOT_FOUND');
  }

  // --- exact retry: same id, same content -> original result, no new state ---
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv, payload: firstPayload, attestationId: firstId,
    }));
    check('same id + same content replay returns 200 replayed', r.status === 200 && r.json?.replayed === true,
      `status=${r.status} body=${JSON.stringify(r.json)}`);
    const h = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(DEVICE)}/head`);
    check('replay does not move head', h.json?.generation === 1);
  }

  // --- same number, different content -> 409, state unchanged ---
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 1, previousGeneration: 0, configSha256: cfg1b.sha },
      attestationId: firstId,
    }));
    check('same id different content -> 409 GENERATION_CONFLICT',
      r.status === 409 && r.json?.error?.code === 'GENERATION_CONFLICT',
      `status=${r.status} body=${JSON.stringify(r.json)}`);
    const h = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(DEVICE)}/head`);
    check('conflict did not change accepted sha', h.json?.configSha256 === cfg1.sha);
  }

  // --- same number, same parsed fields, but different signed bytes (extra field) -> 409 ---
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 1, previousGeneration: 0, configSha256: cfg1.sha, nonce: 'extra-signed-field' },
      attestationId: firstId,
    }));
    check('same id + extra signed JSON field (different bytes) -> 409 GENERATION_CONFLICT',
      r.status === 409 && r.json?.error?.code === 'GENERATION_CONFLICT',
      `status=${r.status} body=${JSON.stringify(r.json)}`);
  }

  // --- GLOBAL idempotency: the same number is accepted by exactly one device ---
  const cfgOther1 = makeConfig(JSON.stringify({ name: 'other-payload-config', version: 1 }));
  const crossId = randomId('att');
  {
    // The other device legitimately onboards with this attestation number.
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: other.keyId, priv: other.priv,
      payload: { deviceId: OTHER_DEVICE, generation: 1, previousGeneration: 0, configSha256: cfgOther1.sha },
      attestationId: crossId,
    }));
    check('cross-device: first device accepts the shared id (201)',
      r.status === 201 && r.json?.head?.deviceId === OTHER_DEVICE && r.json?.head?.generation === 1,
      `status=${r.status} body=${JSON.stringify(r.json)}`);
    const h = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(OTHER_DEVICE)}/head`);
    check('cross-device: accepting device formed its gen-1 head',
      h.status === 200 && h.json?.configSha256 === cfgOther1.sha, JSON.stringify(h.json));

    // Exact retry by the winning device replays the original result.
    const replay = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: other.keyId, priv: other.priv,
      payload: { deviceId: OTHER_DEVICE, generation: 1, previousGeneration: 0, configSha256: cfgOther1.sha },
      attestationId: crossId,
    }));
    check('cross-device: exact retry on the winner replays (200)',
      replay.status === 200 && replay.json?.replayed === true,
      `status=${replay.status} body=${JSON.stringify(replay.json)}`);

    // The first device reusing the same number (different device/key/payload)
    // must conflict and neither create its submission nor move the winner.
    const clash = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 2, previousGeneration: 1, configSha256: cfg2.sha },
      attestationId: crossId,
    }));
    check('cross-device: second device reusing the id -> 409 GENERATION_CONFLICT',
      clash.status === 409 && clash.json?.error?.code === 'GENERATION_CONFLICT',
      `status=${clash.status} body=${JSON.stringify(clash.json)}`);
    const hMine = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(DEVICE)}/head`);
    const hOther = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(OTHER_DEVICE)}/head`);
    check('cross-device: conflict advanced neither head (mine=1, other=1)',
      hMine.json?.generation === 1 && hOther.json?.generation === 1 && hOther.json?.configSha256 === cfgOther1.sha,
      `mine=${JSON.stringify(hMine.json)} other=${JSON.stringify(hOther.json)}`);
  }

  // --- stale predecessor (jump claiming prev=0 while head is 1) ---
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 5, previousGeneration: 0, configSha256: cfg2.sha },
    }));
    check('stale/fork predecessor -> 409 PREDECESSOR_MISMATCH',
      r.status === 409 && r.json?.error?.code === 'PREDECESSOR_MISMATCH',
      `status=${r.status} body=${JSON.stringify(r.json)}`);
  }

  // --- rollback: same generation as head with different content (prev == head, gen == head) ---
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 1, previousGeneration: 1, configSha256: cfg1b.sha },
    }));
    check('same-generation different content -> 409 GENERATION_CONFLICT',
      r.status === 409 && r.json?.error?.code === 'GENERATION_CONFLICT',
      `status=${r.status} body=${JSON.stringify(r.json)}`);
  }

  // --- rollback: older generation than head -> 409, never applied ---
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 1, previousGeneration: 1, configSha256: cfg1.sha },
      attestationId: randomId('att'),
    }));
    check('rollback to older/equal generation -> 409 without advancing state',
      r.status === 409,
      `status=${r.status} body=${JSON.stringify(r.json)}`);
  }

  // --- unknown key ---
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: 'no-such-key', priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 2, previousGeneration: 1, configSha256: cfg2.sha },
    }));
    check('unknown keyId -> 401 UNKNOWN_KEY', r.status === 401 && r.json?.error?.code === 'UNKNOWN_KEY',
      `status=${r.status} body=${JSON.stringify(r.json)}`);
  }

  // --- valid key from another device signing this device's payload ---
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: other.keyId, priv: other.priv,
      payload: { deviceId: DEVICE, generation: 2, previousGeneration: 1, configSha256: cfg2.sha },
    }));
    check('foreign device key -> 403 KEY_DEVICE_MISMATCH',
      r.status === 403 && r.json?.error?.code === 'KEY_DEVICE_MISMATCH',
      `status=${r.status} body=${JSON.stringify(r.json)}`);
  }

  // --- bad signature (flip a byte) ---
  {
    const good = envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 2, previousGeneration: 1, configSha256: cfg2.sha },
    });
    const sig = Buffer.from(good.signatureBase64, 'base64');
    sig[0] ^= 0xff;
    good.signatureBase64 = sig.toString('base64');
    const r = await api(baseUrl, 'POST', '/api/attestations', good);
    check('tampered signature -> 401 INVALID_SIGNATURE',
      r.status === 401 && r.json?.error?.code === 'INVALID_SIGNATURE',
      `status=${r.status} body=${JSON.stringify(r.json)}`);
    const h = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(DEVICE)}/head`);
    check('bad signature did not advance state', h.json?.generation === 1);
  }

  // --- legit chain advance to generation 2 ---
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 2, previousGeneration: 1, configSha256: cfg2.sha },
    }));
    check('chain advance gen 2 (prev 1) accepted', r.status === 201 && r.json?.head?.generation === 2,
      `status=${r.status} body=${JSON.stringify(r.json)}`);
  }

  // --- concurrent race: two different gen-3/prev-2 configs in parallel ---
  const cfg3a = makeConfig(JSON.stringify({ name: 'payload-config', version: '3', branch: 'a' }));
  const cfg3b = makeConfig(JSON.stringify({ name: 'payload-config', version: '3', branch: 'b' }));
  {
    const [ra, rb] = await Promise.all([
      api(baseUrl, 'POST', '/api/attestations', envelope({
        keyId: mine.keyId, priv: mine.priv,
        payload: { deviceId: DEVICE, generation: 3, previousGeneration: 2, configSha256: cfg3a.sha },
      })),
      api(baseUrl, 'POST', '/api/attestations', envelope({
        keyId: mine.keyId, priv: mine.priv,
        payload: { deviceId: DEVICE, generation: 3, previousGeneration: 2, configSha256: cfg3b.sha },
      })),
    ]);
    const codes = [ra.status, rb.status].sort().join(',');
    const exactlyOneAccepted = [ra.status, rb.status].filter((s) => s === 201).length === 1;
    const loser = ra.status === 201 ? rb : ra;
    check('race: exactly one of two concurrent gen-3 writers accepted',
      exactlyOneAccepted && loser.status === 409 &&
        [ErrorCodeSafe(loser)].every((c) => ['GENERATION_CONFLICT', 'PREDECESSOR_MISMATCH'].includes(c)),
      `statuses=${codes} loser=${JSON.stringify(loser.json)}`);
    const h = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(DEVICE)}/head`);
    const winnerSha = ra.status === 201 ? cfg3a.sha : cfg3b.sha;
    check('race: unique head at generation 3 equals winner sha',
      h.status === 200 && h.json?.generation === 3 && h.json?.configSha256 === winnerSha,
      JSON.stringify(h.json));

    // The loser retried as an exact replay? It has a fresh attestationId, so it
    // must still conflict; and a fresh gen-4 chain extension must still work,
    // proving the winner durably became the unique predecessor.
    const cfg4 = makeConfig(JSON.stringify({ name: 'payload-config', version: 4 }));
    const r4 = await api(baseUrl, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: 4, previousGeneration: 3, configSha256: cfg4.sha },
    }));
    check('chain continues from unique race winner (gen 4)', r4.status === 201 && r4.json?.head?.generation === 4,
      `status=${r4.status} body=${JSON.stringify(r4.json)}`);
  }

  // --- cross-device concurrent race: both devices claim one fresh id in parallel ---
  {
    const crossRaceId = randomId('att');
    const cfgMine5 = makeConfig(JSON.stringify({ name: 'payload-config', version: 5 }));
    const cfgOther2 = makeConfig(JSON.stringify({ name: 'other-payload-config', version: 2 }));
    const [ra, rb] = await Promise.all([
      api(baseUrl, 'POST', '/api/attestations', envelope({
        keyId: mine.keyId, priv: mine.priv,
        payload: { deviceId: DEVICE, generation: 5, previousGeneration: 4, configSha256: cfgMine5.sha },
        attestationId: crossRaceId,
      })),
      api(baseUrl, 'POST', '/api/attestations', envelope({
        keyId: other.keyId, priv: other.priv,
        payload: { deviceId: OTHER_DEVICE, generation: 2, previousGeneration: 1, configSha256: cfgOther2.sha },
        attestationId: crossRaceId,
      })),
    ]);
    const accepted = [ra, rb].filter((r) => r.status === 201);
    const losers = [ra, rb].filter((r) => r.status !== 201);
    check('cross-device race: exactly one of two devices accepts the shared id',
      accepted.length === 1 && losers.length === 1 &&
        losers[0].status === 409 && losers[0].json?.error?.code === 'GENERATION_CONFLICT',
      `statuses=${[ra.status, rb.status].join(',')} loser=${JSON.stringify(losers[0]?.json)}`);

    const winner = accepted[0]?.json?.head?.deviceId;
    const hMine = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(DEVICE)}/head`);
    const hOther = await api(baseUrl, 'GET', `/api/devices/${encodeURIComponent(OTHER_DEVICE)}/head`);
    if (winner === DEVICE) {
      finalDeviceGeneration = 5;
      check('cross-device race: DEVICE advanced to 5, OTHER stayed at 1',
        hMine.json?.generation === 5 && hMine.json?.configSha256 === cfgMine5.sha &&
          hOther.json?.generation === 1 && hOther.json?.configSha256 === cfgOther1.sha,
        `mine=${JSON.stringify(hMine.json)} other=${JSON.stringify(hOther.json)}`);
    } else {
      finalOtherGeneration = 2;
      check('cross-device race: OTHER advanced to 2, DEVICE stayed at 4',
        hOther.json?.generation === 2 && hOther.json?.configSha256 === cfgOther2.sha &&
          hMine.json?.generation === 4,
        `mine=${JSON.stringify(hMine.json)} other=${JSON.stringify(hOther.json)}`);
    }
    // Retrying the loser's exact request is still a conflict (same id, now taken).
    const loserRetry = winner === DEVICE
      ? envelope({ keyId: other.keyId, priv: other.priv,
          payload: { deviceId: OTHER_DEVICE, generation: 2, previousGeneration: 1, configSha256: cfgOther2.sha },
          attestationId: crossRaceId })
      : envelope({ keyId: mine.keyId, priv: mine.priv,
          payload: { deviceId: DEVICE, generation: 5, previousGeneration: 4, configSha256: cfgMine5.sha },
          attestationId: crossRaceId });
    const rr = await api(baseUrl, 'POST', '/api/attestations', loserRetry);
    check('cross-device race: loser deterministic conflict on serial retry too',
      rr.status === 409 && rr.json?.error?.code === 'GENERATION_CONFLICT',
      `status=${rr.status} body=${JSON.stringify(rr.json)}`);
  }

  // --- malformed inputs get stable 400 codes ---
  {
    const r = await fetch(new URL('/api/attestations', baseUrl), { method: 'POST', body: 'not-json' });
    const j = await r.json().catch(() => null);
    check('malformed JSON envelope -> 400 INVALID_REQUEST', r.status === 400 && j?.error?.code === 'INVALID_REQUEST');
  }
  {
    const r = await api(baseUrl, 'POST', '/api/attestations', {
      attestationId: 'x', keyId: mine.keyId, payloadBase64: '###', signatureBase64: signPayload(mine.priv, Buffer.from('x')),
    });
    check('non-base64 payload -> 400 INVALID_REQUEST', r.status === 400 && r.json?.error?.code === 'INVALID_REQUEST',
      JSON.stringify(r.json));
  }
  {
    const payloadBytes = Buffer.from(JSON.stringify({ deviceId: DEVICE, generation: 1 }), 'utf8');
    const r = await api(baseUrl, 'POST', '/api/attestations', {
      attestationId: 'y', keyId: mine.keyId,
      payloadBase64: payloadBytes.toString('base64'),
      signatureBase64: signPayload(mine.priv, payloadBytes),
    });
    check('payload missing fields -> 400 INVALID_PAYLOAD', r.status === 400 && r.json?.error?.code === 'INVALID_PAYLOAD',
      JSON.stringify(r.json));
  }

  return { crossId, finalDeviceGeneration, finalOtherGeneration };
}

function ErrorCodeSafe(r) {
  return r?.json?.error?.code;
}

async function remoteMode() {
  const baseUrl = process.env.BASE_URL;
  const keys = loadKeys(process.env.SMOKE_KEYS_FILE);
  console.log(`SMOKE against remote ${baseUrl} (restart/persistence checks skipped)`);
  await scenario(baseUrl, keys);
}

async function selfContainedMode() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'att-smoke-'));
  const dataDir = path.join(root, 'data');
  const keysFile = path.join(root, 'device-keys.json');
  const fixturesFile = path.join(root, 'fixtures.json');
  fs.mkdirSync(dataDir, { recursive: true });

  // Generate keys with node:crypto via signing helpers.
  const k1Raw = cryptoGenerate();
  const k2Raw = cryptoGenerate();
  const manifest = {
    keys: { [KEY_ID]: k1Raw.pubB64, [OTHER_KEY_ID]: k2Raw.pubB64 },
    devices: {
      [DEVICE]: { keyId: KEY_ID, publicKey: k1Raw.pubB64 },
      [OTHER_DEVICE]: { keyId: OTHER_KEY_ID, publicKey: k2Raw.pubB64 },
    },
  };
  fs.writeFileSync(keysFile, JSON.stringify(manifest, null, 2));
  fs.writeFileSync(fixturesFile, JSON.stringify({
    devices: {
      [DEVICE]: { keyId: KEY_ID, seedBase64: k1Raw.seedB64, publicKeyBase64: k1Raw.pubB64 },
      [OTHER_DEVICE]: { keyId: OTHER_KEY_ID, seedBase64: k2Raw.seedB64, publicKeyBase64: k2Raw.pubB64 },
    },
  }));

  // Sanity: declared public key actually matches the signing seed.
  {
    const priv = privateKeyFromSeed(Buffer.from(k1Raw.seedB64, 'base64'));
    const pub = publicKeyFromRaw(Buffer.from(k1Raw.pubB64, 'base64'));
    const probe = Buffer.from('probe');
    const sig = signPayload(priv, probe);
    const ok = cryptoVerify(pub, probe, Buffer.from(sig, 'base64'));
    check('generated fixture keypair is internally consistent', ok);
  }

  const env = { PORT: '0', DATA_DIR: dataDir, DEVICE_KEYS_FILE: keysFile };
  let server = await startServer({ env });
  const baseUrl = `http://127.0.0.1:${server.port}`;
  console.log(`SMOKE self-contained server on ${baseUrl} (data ${dataDir})`);

  const summary = await scenario(baseUrl, loadKeys(fixturesFile));

  // --- hard restart: same DATA_DIR, new process, heads must be recovered ---
  const code = await server.stop('SIGTERM');
  check('server exits cleanly on SIGTERM', code === 0, `exit=${code}`);

  server = await startServer({ env });
  const baseUrl2 = `http://127.0.0.1:${server.port}`;
  {
    const h = await api(baseUrl2, 'GET', `/api/devices/${encodeURIComponent(DEVICE)}/head`);
    check('after restart DEVICE head is recovered at the pre-restart generation',
      h.status === 200 && h.json?.generation === summary.finalDeviceGeneration &&
        typeof h.json?.configSha256 === 'string',
      JSON.stringify(h.json));
    const ho = await api(baseUrl2, 'GET', `/api/devices/${encodeURIComponent(OTHER_DEVICE)}/head`);
    check('after restart OTHER head is recovered at the pre-restart generation',
      ho.status === 200 && ho.json?.generation === summary.finalOtherGeneration,
      JSON.stringify(ho.json));
  }
  {
    // Post-restart dedup verdict is identical: exact replay on the winning
    // device returns 200, reuse of the same number on the other device is 409
    // and advances neither head.
    const keys = loadKeys(fixturesFile);
    const mine = keys[DEVICE];
    const other = keys[OTHER_DEVICE];
    const cfgOther1 = makeConfig(JSON.stringify({ name: 'other-payload-config', version: 1 }));
    const cfgNext = makeConfig(JSON.stringify({ name: 'payload-config', version: 'post-restart' }));

    const replay = await api(baseUrl2, 'POST', '/api/attestations', envelope({
      keyId: other.keyId, priv: other.priv,
      payload: { deviceId: OTHER_DEVICE, generation: 1, previousGeneration: 0, configSha256: cfgOther1.sha },
      attestationId: summary.crossId,
    }));
    check('after restart shared id still replays on the original winner',
      replay.status === 200 && replay.json?.replayed === true,
      `status=${replay.status} body=${JSON.stringify(replay.json)}`);

    const clash = await api(baseUrl2, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: {
        deviceId: DEVICE,
        generation: summary.finalDeviceGeneration + 1,
        previousGeneration: summary.finalDeviceGeneration,
        configSha256: cfgNext.sha,
      },
      attestationId: summary.crossId,
    }));
    check('after restart shared id reused by another device still -> 409',
      clash.status === 409 && clash.json?.error?.code === 'GENERATION_CONFLICT',
      `status=${clash.status} body=${JSON.stringify(clash.json)}`);

    // After restart, predecessor chain continues to validate against recovered head.
    const prev = (await api(baseUrl2, 'GET', `/api/devices/${encodeURIComponent(DEVICE)}/head`)).json;
    const r = await api(baseUrl2, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: {
        deviceId: DEVICE,
        generation: prev.generation + 1,
        previousGeneration: prev.generation,
        configSha256: cfgNext.sha,
      },
    }));
    check('after restart chain advances one generation',
      r.status === 201 && r.json?.head?.generation === prev.generation + 1,
      `status=${r.status} body=${JSON.stringify(r.json)}`);
    // old predecessor is now stale
    const stale = await api(baseUrl2, 'POST', '/api/attestations', envelope({
      keyId: mine.keyId, priv: mine.priv,
      payload: { deviceId: DEVICE, generation: prev.generation + 2, previousGeneration: 3, configSha256: cfgNext.sha },
    }));
    check('after restart stale predecessor rejected', stale.status === 409 && stale.json?.error?.code === 'PREDECESSOR_MISMATCH');
  }

  const finalCode = await server.stop('SIGTERM');
  check('restarted server exits cleanly too', finalCode === 0, `exit=${finalCode}`);

  fs.rmSync(root, { recursive: true, force: true });
}

function cryptoGenerate() {
  const k = generateDeviceKey();
  return { pubB64: k.publicRaw.toString('base64'), seedB64: k.seed.toString('base64') };
}

function cryptoVerify(pub, msg, sig) {
  return crypto.verify(null, msg, pub, sig);
}

await (async () => {
  const remote = process.env.BASE_URL;
  try {
    if (remote) {
      await remoteMode();
    } else {
      await selfContainedMode();
    }
  } catch (err) {
    failures += 1;
    console.error('SMOKE HARNESS ERROR:', err?.stack || err);
  }

  const passed = checks.filter((c) => c.ok).length;
  console.log(`\nSMOKE SUMMARY: ${passed}/${checks.length} checks passed`);
  if (failures > 0) {
    console.error('SMOKE FAILED');
    process.exit(1);
  }
  console.log('SMOKE OK');
  process.exit(0);
})();
