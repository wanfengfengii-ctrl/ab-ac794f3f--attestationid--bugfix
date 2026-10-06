#!/usr/bin/env node
// Generates deployment-declared device public keys and the (test-only)
// matching private key fixtures used by the smoke/verify job.
//
//   node tools/gen-keys.mjs [--out config/device-keys.json] [--fixtures test/fixtures/smoke-keys.json]
//
// Production deployments: replace config/device-keys.json with keys generated
// in your KMS/HSM and never ship the fixtures file.
import fs from 'node:fs';
import path from 'node:path';
import { generateDeviceKey, rawPublic } from './signing.mjs';

const args = process.argv.slice(2);
function flag(name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}

const outFile = path.resolve(flag('--out', 'config/device-keys.json'));
const fixtureFile = path.resolve(flag('--fixtures', 'test/fixtures/smoke-keys.json'));

const DEVICES = [
  { deviceId: 'SAT-A01', keyId: 'sat-a01-ed25519-1' },
  { deviceId: 'SAT-B02', keyId: 'sat-b02-ed25519-1' },
];

const manifest = { keys: {}, devices: {} };
const fixtures = { generatedAt: new Date().toISOString(), note: 'TEST FIXTURE ONLY - never use in production', devices: {} };

for (const { deviceId, keyId } of DEVICES) {
  const k = generateDeviceKey();
  manifest.keys[keyId] = k.publicRaw.toString('base64');
  manifest.devices[deviceId] = { keyId, publicKey: k.publicRaw.toString('base64') };
  fixtures.devices[deviceId] = { keyId, seedBase64: k.seed.toString('base64'), publicKeyBase64: k.publicRaw.toString('base64') };
}

// An extra declared-but-unbound key, useful for negative testing.
{
  const k = generateDeviceKey();
  manifest.keys['pool-ed25519-1'] = k.publicRaw.toString('base64');
}

// Touch import so tree-shakers/linters see usage; rawPublic re-exported for tooling.
void rawPublic;

fs.mkdirSync(path.dirname(outFile), { recursive: true });
fs.mkdirSync(path.dirname(fixtureFile), { recursive: true });
fs.writeFileSync(outFile, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
fs.writeFileSync(fixtureFile, `${JSON.stringify(fixtures, null, 2)}\n`, { mode: 0o600 });

console.log(`wrote ${path.relative(process.cwd(), outFile)} (${DEVICES.length} devices)`);
console.log(`wrote ${path.relative(process.cwd(), fixtureFile)} (TEST FIXTURE)`);
