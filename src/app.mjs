import { Buffer } from 'node:buffer';
import { AppError, ErrorCode } from './errors.mjs';
import { config } from './config.mjs';

/**
 * Build the request-handling app. Exported separately from server.mjs so tests
 * can drive it without binding a port.
 */
export function createApp(service, deps = {}) {
  const maxBodyBytes = deps.maxBodyBytes ?? config.maxPayloadBytes * 16;

  return async function app(req, res) {
    const start = Date.now();
    try {
      const url = new URL(req.url, 'http://localhost');
      const method = req.method ?? 'GET';

      if (method === 'GET' && (url.pathname === '/health' || url.pathname === '/healthz')) {
        return json(res, 200, {
          status: 'ok',
          uptimeSeconds: Math.round(process.uptime()),
          timestamp: new Date().toISOString(),
        });
      }

      if (method === 'POST' && url.pathname === '/api/attestations') {
        const body = await readJsonBody(req, maxBodyBytes);
        const result = await service.submit(body);
        return json(res, result.replayed ? 200 : 201, result);
      }

      const headMatch = /^\/api\/devices\/([^/]+)\/head$/.exec(url.pathname);
      if (method === 'GET' && headMatch) {
        const deviceId = decodeURIComponent(headMatch[1]);
        return json(res, 200, service.head(deviceId));
      }

      return json(res, 404, {
        error: { code: ErrorCode.ROUTE_NOT_FOUND, message: `cannot ${method} ${url.pathname}` },
      });
    } catch (err) {
      return sendError(res, err, start);
    }
  };
}

async function readJsonBody(req, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) {
      throw new AppError(413, ErrorCode.INVALID_REQUEST, `request body exceeds ${limit} bytes`);
    }
    chunks.push(chunk);
  }
  if (size === 0) {
    throw new AppError(400, ErrorCode.INVALID_REQUEST, 'request body is empty');
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new AppError(400, ErrorCode.INVALID_REQUEST, 'request body is not valid JSON');
  }
  return parsed;
}

function sendError(res, err, start) {
  if (err instanceof AppError) {
    return json(res, err.status, {
      error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) },
    });
  }
  // Do not leak internals; keep a stable code plus request id for correlation.
  const requestId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  // eslint-disable-next-line no-console
  console.error(JSON.stringify({ level: 'error', requestId, msg: err?.message, stack: err?.stack }));
  return json(res, 500, {
    error: { code: ErrorCode.INTERNAL_ERROR, message: 'internal server error', requestId },
  });
}

function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}
