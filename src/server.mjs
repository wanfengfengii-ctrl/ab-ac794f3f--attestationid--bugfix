import { createServer } from 'node:http';
import { config } from './config.mjs';
import { DeviceRegistry } from './registry.mjs';
import { AttestationStore } from './store.mjs';
import { createAttestationService } from './attestation.mjs';
import { createApp } from './app.mjs';

async function main() {
  const registry = DeviceRegistry.fromFile(config.deviceKeysFile);
  const store = new AttestationStore(config.dataDir);
  await store.init();
  const service = createAttestationService({
    store,
    registry,
    maxPayloadBytes: config.maxPayloadBytes,
  });
  const app = createApp(service);
  const server = createServer(app);

  await new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(config.port, resolve);
  });

  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : config.port;

  const shutdown = (signal) => {
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ level: 'info', msg: `received ${signal}, shutting down` }));
    server.close(() => process.exit(0));
    // Hard exit if in-flight connections linger.
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Machine-readable readiness line consumed by tests, smoke and compose healthcheck.
  console.log(`READY port=${port}`);
  // eslint-disable-next-line no-console
  console.error(JSON.stringify({ level: 'info', msg: 'attestation gateway listening', port }));
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(JSON.stringify({ level: 'fatal', msg: err?.message, stack: err?.stack }));
  process.exit(1);
});
