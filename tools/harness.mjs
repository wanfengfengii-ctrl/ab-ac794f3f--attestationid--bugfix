import { spawn } from 'node:child_process';
import path from 'node:path';

/**
 * Spawn src/server.mjs with the given env. PORT may be 0 (ephemeral); the
 * harness parses the "READY port=<n>" line. Returns { child, port, stop }.
 */
export async function startServer({ env = {}, cwd = process.cwd(), expectReady = true } = {}) {
  const child = spawn(process.execPath, [path.join(cwd, 'src', 'server.mjs')], {
    cwd,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  child.stderr.on('data', (d) => {
    stderr += d.toString();
  });

  let port = null;
  if (expectReady) {
    port = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`server did not become ready in 10s\n${stderr}`)), 10_000);
      const onData = (chunk) => {
        const line = chunk.toString();
        const m = /READY port=(\d+)/.exec(line);
        if (m) {
          clearTimeout(timer);
          child.stdout.off('data', onData);
          resolve(Number(m[1]));
        }
      };
      child.stdout.on('data', onData);
      child.on('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`server exited early with code ${code}\n${stderr}`));
      });
    });
  }

  const stop = (signal = 'SIGTERM') =>
    new Promise((resolve) => {
      if (child.exitCode !== null) return resolve(child.exitCode);
      child.on('exit', (code) => resolve(code ?? 0));
      child.kill(signal);
    });

  return { child, port, stop, get stderr() { return stderr; } };
}

export async function waitForExit(child, timeoutMs = 10_000) {
  if (child.exitCode !== null) return child.exitCode;
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('process did not exit in time')), timeoutMs);
    child.on('exit', (code) => {
      clearTimeout(t);
      resolve(code ?? 0);
    });
  });
}
