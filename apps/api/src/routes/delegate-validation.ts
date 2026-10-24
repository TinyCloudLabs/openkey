export type DelegateErrorCode =
  | 'invalid_permissions'
  | 'invalid_expiry'
  | 'delegation_prepare_failed';

export interface DelegateErrorDetail {
  path: string;
  message: string;
  value?: string;
  expected?: string;
  expectedPrefix?: string;
  suggestion?: string;
}

export interface DelegateErrorResponse {
  error: string;
  code: DelegateErrorCode;
  message: string;
  details?: DelegateErrorDetail[];
}

export class DelegateRequestError extends Error {
  constructor(
    public code: DelegateErrorCode,
    message: string,
    public details?: DelegateErrorDetail[],
  ) {
    super(message);
    this.name = 'DelegateRequestError';
  }
}

export function delegateErrorResponse(
  err: unknown,
  fallbackMessage: string,
  fallbackCode: DelegateErrorCode,
): DelegateErrorResponse {
  const message = err instanceof Error ? err.message : fallbackMessage;
  const response: DelegateErrorResponse = {
    error: message,
    code: err instanceof DelegateRequestError ? err.code : fallbackCode,
    message,
  };

  if (err instanceof DelegateRequestError && err.details?.length) {
    response.details = err.details;
  }

  return response;
}

export function shortServiceName(service: string): string {
  return service.startsWith('tinycloud.')
    ? service.slice('tinycloud.'.length)
    : service;
}

export function normalizeDelegateReason(reason: unknown): string | undefined {
  if (typeof reason !== 'string') return undefined;

  const normalized = reason.replace(/\s+/g, ' ').trim();
  if (!normalized) return undefined;

  return normalized.slice(0, 500);
}

/**
 * The Expiration Time of a SIWE message. Response expiry fields come only
 * from the signed bytes, never from caller-supplied metadata (TC-547).
 */
export function signedSiweExpirationTime(siwe: unknown): string | undefined {
  if (typeof siwe !== 'string') return undefined;
  const expirationTime = siwe.match(/^Expiration Time:\s*(.+)$/im)?.[1]?.trim();
  return expirationTime && !Number.isNaN(Date.parse(expirationTime)) ? expirationTime : undefined;
}
