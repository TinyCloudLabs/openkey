export interface PermissionEntry {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

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

function expectedActionPrefix(service: string): string {
  return `tinycloud.${shortServiceName(service)}/`;
}

function suggestedAction(service: string, action: string): string | undefined {
  const short = shortServiceName(service);
  const expectedPrefix = expectedActionPrefix(service);

  if (!action.includes('/')) {
    return action ? `${expectedPrefix}${action}` : undefined;
  }

  if (action.startsWith(`${short}/`)) {
    return `${expectedPrefix}${action.slice(short.length + 1)}`;
  }

  return undefined;
}

export function validatePermissions(permissions: unknown): PermissionEntry[] {
  if (!Array.isArray(permissions) || permissions.length === 0) {
    throw new DelegateRequestError(
      'invalid_permissions',
      'permissions must be a non-empty array',
      [{
        path: 'permissions',
        message: 'Expected a non-empty array',
        expected: 'non-empty array',
      }],
    );
  }

  return permissions.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new DelegateRequestError(
        'invalid_permissions',
        `permissions[${index}] is not an object`,
        [{
          path: `permissions[${index}]`,
          message: 'Expected an object',
          expected: 'object',
        }],
      );
    }

    const e = entry as Record<string, unknown>;
    if (typeof e.service !== 'string' || !e.service) {
      throw new DelegateRequestError(
        'invalid_permissions',
        `permissions[${index}].service is required`,
        [{
          path: `permissions[${index}].service`,
          message: 'Expected a non-empty service string',
          expected: 'non-empty string',
        }],
      );
    }
    if (typeof e.space !== 'string' || !e.space) {
      throw new DelegateRequestError(
        'invalid_permissions',
        `permissions[${index}].space is required`,
        [{
          path: `permissions[${index}].space`,
          message: 'Expected a non-empty space string',
          expected: 'non-empty string',
        }],
      );
    }
    if (typeof e.path !== 'string') {
      throw new DelegateRequestError(
        'invalid_permissions',
        `permissions[${index}].path must be a string`,
        [{
          path: `permissions[${index}].path`,
          message: 'Expected a path string',
          expected: 'string',
        }],
      );
    }
    if (!Array.isArray(e.actions) || e.actions.length === 0 || e.actions.some((a) => typeof a !== 'string')) {
      throw new DelegateRequestError(
        'invalid_permissions',
        `permissions[${index}].actions must be a non-empty string[]`,
        [{
          path: `permissions[${index}].actions`,
          message: 'Expected a non-empty array of action strings',
          expected: 'non-empty string[]',
        }],
      );
    }

    const expectedPrefix = expectedActionPrefix(e.service);
    const actions = e.actions as string[];
    for (const [actionIndex, action] of actions.entries()) {
      if (!action.startsWith(expectedPrefix) || action.length === expectedPrefix.length) {
        const path = `permissions[${index}].actions[${actionIndex}]`;
        throw new DelegateRequestError(
          'invalid_permissions',
          `${path} must be fully qualified for service ${e.service}`,
          [{
            path,
            message: `Action must start with ${expectedPrefix} and include an action name`,
            value: action,
            expectedPrefix,
            suggestion: suggestedAction(e.service, action),
          }],
        );
      }
    }

    return {
      service: e.service,
      space: e.space,
      path: e.path,
      actions,
    };
  });
}

export function normalizeDelegateReason(reason: unknown): string | undefined {
  if (typeof reason !== 'string') return undefined;

  const normalized = reason.replace(/\s+/g, ' ').trim();
  if (!normalized) return undefined;

  return normalized.slice(0, 500);
}
