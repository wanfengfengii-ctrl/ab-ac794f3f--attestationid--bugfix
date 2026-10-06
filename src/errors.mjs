// Stable application error codes. These strings are part of the API contract
// and must not be changed casually: operations teams key alerts and runbooks
// off them.
export const ErrorCode = Object.freeze({
  // 400 - envelope/payload malformed
  INVALID_REQUEST: 'INVALID_REQUEST',
  INVALID_PAYLOAD: 'INVALID_PAYLOAD',
  // 401 - key material / signature problems
  UNKNOWN_KEY: 'UNKNOWN_KEY',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  // 403 - signature is valid but the key is not entitled for the device
  KEY_DEVICE_MISMATCH: 'KEY_DEVICE_MISMATCH',
  // 409 - ordering / fork / rollback conflicts, state is never advanced
  GENERATION_CONFLICT: 'GENERATION_CONFLICT',
  PREDECESSOR_MISMATCH: 'PREDECESSOR_MISMATCH',
  GENERATION_NOT_ADVANCED: 'GENERATION_NOT_ADVANCED',
  // 404
  DEVICE_NOT_FOUND: 'DEVICE_NOT_FOUND',
  ROUTE_NOT_FOUND: 'ROUTE_NOT_FOUND',
  // 500
  INTERNAL_ERROR: 'INTERNAL_ERROR',
});

export class AppError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}
