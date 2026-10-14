import { randomUUID } from 'node:crypto';
import type { ErrorHandler, MiddlewareHandler } from 'hono';

export type ApiEnv = { Variables: { requestId: string } };

type LogFields = {
  method?: string;
  route?: string;
  status?: number;
  ms?: number;
  request_id?: string;
  error_name?: string;
  error_code?: string;
};

const EVENT_PATTERN = /^[a-z0-9_.:-]{1,80}$/;
const ERROR_CODE_PATTERN = /^[A-Za-z0-9_.-]{1,40}$/;
const ERROR_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9-]{8,64}$/;

export function log(level: 'debug' | 'info' | 'warn' | 'error', event: string, fields: LogFields = {}): void {
  if (!EVENT_PATTERN.test(event)) throw new TypeError('Invalid log event');
  const line: Record<string, string | number> = { ts: new Date().toISOString(), level, event };
  if (fields.method !== undefined) line.method = fields.method;
  if (fields.route !== undefined) line.route = fields.route;
  if (fields.status !== undefined) line.status = fields.status;
  if (fields.ms !== undefined) line.ms = fields.ms;
  if (fields.request_id !== undefined) line.request_id = fields.request_id;
  if (fields.error_name !== undefined && ERROR_NAME_PATTERN.test(fields.error_name)) line.error_name = fields.error_name;
  if (fields.error_code !== undefined && ERROR_CODE_PATTERN.test(fields.error_code)) line.error_code = fields.error_code;
  console.log(JSON.stringify(line));
}

function errorFields(error: unknown): Pick<LogFields, 'error_name' | 'error_code'> {
  if (typeof error !== 'object' || error === null) return {};
  const candidate = error as { name?: unknown; code?: unknown };
  const name = typeof candidate.name === 'string' && ERROR_NAME_PATTERN.test(candidate.name)
    ? candidate.name
    : error instanceof Error ? 'Error' : undefined;
  const code = typeof candidate.code === 'string' && ERROR_CODE_PATTERN.test(candidate.code)
    ? candidate.code
    : undefined;
  return { ...(name ? { error_name: name } : {}), ...(code ? { error_code: code } : {}) };
}

export function logError(level: 'warn' | 'error', event: string, error: unknown, fields: LogFields = {}): void {
  log(level, event, { ...fields, ...errorFields(error) });
}

export const requestLogger: MiddlewareHandler<ApiEnv> = async (c, next) => {
  const incomingId = c.req.header('X-Request-Id');
  const requestId = incomingId && REQUEST_ID_PATTERN.test(incomingId) ? incomingId : randomUUID();
  const startedAt = performance.now();
  c.set('requestId', requestId);
  c.header('X-Request-Id', requestId);
  await next();
  const route = c.req.routePath || '<unmatched>';
  log('info', 'request', {
    method: c.req.method,
    route,
    status: c.res.status,
    ms: Math.round(performance.now() - startedAt),
    request_id: requestId,
  });
};

export const apiErrorHandler: ErrorHandler<ApiEnv> = (error, c) => {
  log('error', 'api_error', {
    ...errorFields(error),
    route: c.req.routePath || '<unmatched>',
    request_id: c.get('requestId'),
  });
  return c.json({ error: 'Internal server error' }, 500);
};
