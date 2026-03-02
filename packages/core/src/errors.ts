/**
 * Unified error codes across all OpenKey SDKs.
 */
export type OpenKeyErrorCode =
  | 'USER_CANCELLED'
  | 'POPUP_BLOCKED'
  | 'TIMEOUT'
  | 'NO_KEY'
  | 'UNAUTHORIZED'
  | 'STATE_MISMATCH'
  | 'NETWORK_ERROR'
  | 'UNKNOWN';

/**
 * Error class for all OpenKey SDK errors.
 */
export class OpenKeyError extends Error {
  constructor(
    public code: OpenKeyErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'OpenKeyError';
  }
}
