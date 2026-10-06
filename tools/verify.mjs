#!/usr/bin/env node
// One-shot verification job used by the "verify" compose service.
// Runs, in order:
//   1) unit/integration tests   (node --test test/)
//   2) build check              (syntax + manifests + module graph)
//   3) signature acceptance smoke (live server, races, restart/persistence)
// Aggregates the result into a single exit code and always exits on its own.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');

const stages = [
  { name: 'tests', cmd: process.execPath, args: ['--test'] },
  { name: 'build-check', cmd: process.execPath, args: [path.join('tools', 'build-check.mjs')] },
  { name: 'smoke', cmd: process.execPath, args: [path.join('tools', 'smoke.mjs')] },
];

function runStage(stage) {
  return new Promise((resolve) => {
    console.log(`\n===== VERIFY STAGE: ${stage.name} =====`);
    const child = spawn(stage.cmd, stage.args, {
      cwd: root,
      env: process.env,
      stdio: 'inherit',
    });
    child.on('error', (err) => {
      console.error(`stage ${stage.name} failed to start: ${err.message}`);
      resolve(1);
    });
    child.on('exit', (code, signal) => {
      if (code === 0) {
        console.log(`----- ${stage.name}: OK -----`);
        resolve(0);
      } else {
        console.error(`----- ${stage.name}: FAILED (exit=${code ?? 'null'} signal=${signal ?? '-'}) -----`);
        resolve(code && code > 0 ? code : 1);
      }
    });
  });
}

let failed = 0;
for (const stage of stages) {
  const code = await runStage(stage);
  if (code !== 0) {
    failed += 1;
    // Keep going so one report shows every broken stage (except smoke, which is
    // pointless when the build is broken — still cheap to attempt in this project).
  }
}

console.log('\n===== VERIFY SUMMARY =====');
if (failed > 0) {
  console.error(`VERIFY FAILED: ${failed} stage(s) failed`);
  process.exit(1);
}
console.log('VERIFY OK: tests, build check and acceptance smoke all passed');
process.exit(0);
