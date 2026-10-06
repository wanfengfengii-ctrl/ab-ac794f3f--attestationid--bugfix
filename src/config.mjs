import path from 'node:path';

function num(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new Error(`Environment variable ${name} must be an integer between 0 and 65535, got: ${raw}`);
  }
  return n;
}

const root = process.cwd();

export const config = Object.freeze({
  // PORT=0 lets the OS pick a free port (used by tests/smoke); the chosen port
  // is announced as a READY line on stdout.
  port: num('PORT', 8080),
  dataDir: process.env.DATA_DIR
    ? path.resolve(process.env.DATA_DIR)
    : path.resolve(root, 'data'),
  deviceKeysFile: process.env.DEVICE_KEYS_FILE
    ? path.resolve(process.env.DEVICE_KEYS_FILE)
    : path.resolve(root, 'config', 'device-keys.json'),
  // 1 MiB request envelope, 64 KiB decoded attestation payload.
  maxBodyBytes: 1 * 1024 * 1024,
  maxPayloadBytes: 64 * 1024,
});
