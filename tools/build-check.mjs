#!/usr/bin/env node
// Lightweight zero-dependency build check: syntax-check every JS file,
// validate JSON manifests, and confirm the server module graph imports.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const root = process.cwd();
let failures = 0;

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.git')) continue;
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out);
    else if (entry.name.endsWith('.mjs') || entry.name.endsWith('.js')) out.push(p);
  }
  return out;
}

const files = walk(path.join(root, 'src'))
  .concat(walk(path.join(root, 'tools')))
  .concat(walk(path.join(root, 'test')));

let checked = 0;
for (const file of files) {
  const r = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  checked += 1;
  if (r.status !== 0) {
    failures += 1;
    console.error(`SYNTAX FAIL ${path.relative(root, file)}\n${r.stderr}`);
  }
}
console.log(`syntax checked ${checked} files`);

for (const f of ['package.json']) {
  try {
    JSON.parse(fs.readFileSync(path.join(root, f), 'utf8'));
  } catch (err) {
    failures += 1;
    console.error(`JSON FAIL ${f}: ${err.message}`);
  }
}
const manifestPath = path.join(root, 'config', 'device-keys.json');
if (fs.existsSync(manifestPath)) {
  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (!manifest.devices || !manifest.keys) throw new Error('manifest needs "devices" and "keys"');
  } catch (err) {
    failures += 1;
    console.error(`MANIFEST FAIL: ${err.message}`);
  }
}

// Import the library module graph (not server.mjs, which binds a port on import).
for (const m of ['src/errors.mjs', 'src/config.mjs', 'src/registry.mjs', 'src/store.mjs', 'src/attestation.mjs', 'src/app.mjs']) {
  try {
    await import(pathToFileURL(path.join(root, m)).href);
  } catch (err) {
    failures += 1;
    console.error(`IMPORT FAIL ${m}: ${err.message}`);
  }
}

if (failures > 0) {
  console.error(`BUILD CHECK FAILED (${failures} problem(s))`);
  process.exit(1);
}
console.log('BUILD CHECK OK');
