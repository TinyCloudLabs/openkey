import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { ErrorHandler, MiddlewareHandler } from 'hono';

export type ApiEnv = { Variables: { requestId: string } };
type LogLevel = 'debug' | 'info' | 'warn' | 'error';
type ErrorFields = { error_name?: string; error_code?: string };
type RequestContext = { requestId: string };

const requestContext = new AsyncLocalStorage<RequestContext>();
const EVENTS = {
  better_auth: true, otp_delivery_unconfigured: true, auth_key_generated: true, auth_key_generation_failed: true,
  auth_email_signup_confirmation_required: true, auth_email_signup_confirmed: true, auth_email_signup_refused: true,
  analytics_token_exchange_failed: true, analytics_unique_user_failed: true, analytics_token_tracking_failed: true,
  analytics_authorization_failed: true, analytics_authorization_tracking_failed: true, oauth_client_scopes_updated: true,
  oauth_client_scopes_update_failed: true, api_starting: true, request: true, api_error: true,
  delegate_session_activation_warning: true, delegate_session_activation_failed: true,
  delegate_authorization_context_issue_failed: true, delegate_space_setup_notice_failed: true,
  delegate_origin_bind_failed: true, tinycloud_bootstrap_failed: true, primary_key_changed: true, key_quote_failed: true,
  native_consent_peer_lookup_failed: true, native_consent_key_unseal_failed: true,
  native_consent_activation_after_host_setup_failed: true, native_consent_host_delegation_rejected: true,
  native_consent_activation_did_not_host_space: true, native_consent_host_activation_failed: true,
  oauth_client_create_failed: true, oauth_client_delete_failed: true, oauth_client_update_failed: true,
  tinycloud_bootstrap_background_failed: true, tinycloud_bootstrap_background_completed: true,
  tinycloud_bootstrap_space_registry_completed: true, native_par_valid_request_volume_threshold_reached: true,
  native_par_request_cleanup_failed: true, native_session_proof_cleanup_failed: true,
  scoreboard_protocol_users_call: true, app_sign_in_record_failed: true,
  third_party_console: true, uncaught_exception: true, unhandled_rejection: true, config_invalid: true,
  unlisted_event: true,
} as const satisfies Record<string, true>;
type EventName = keyof typeof EVENTS;
const CONFIG_KEYS: Record<string, true> = { BETTER_AUTH_URL: true };
const ERROR_CODES: Record<string, true> = {
  P2002: true, P2025: true, P2010: true, P2034: true, tinycloud_bootstrap_failed: true,
  tinycloud_bootstrap_crashed: true, tinycloud_bootstrap_in_progress: true,
  tinycloud_bootstrap_expired_request: true, BETTER_AUTH_URL: true, signup_token_invalid: true,
  signup_account_exists: true, quote_report_data_mismatch: true, quote_key_custody_mismatch: true,
  quote_format_invalid: true,
};
const LEVELS: Record<string, true> = { debug: true, info: true, warn: true, error: true };
const METHODS: Record<string, true> = {
  GET: true, POST: true, PUT: true, PATCH: true, DELETE: true, HEAD: true, OPTIONS: true, CONNECT: true, TRACE: true,
};
function safeErrorFields(error: unknown): ErrorFields {
  if (typeof error !== 'object' || error === null) return {};
  try {
    const fields: ErrorFields = {};
    if (error instanceof TypeError) fields.error_name = 'TypeError';
    else if (error instanceof RangeError) fields.error_name = 'RangeError';
    else if (error instanceof ReferenceError) fields.error_name = 'ReferenceError';
    else if (error instanceof SyntaxError) fields.error_name = 'SyntaxError';
    else if (error instanceof URIError) fields.error_name = 'URIError';
    else if (error instanceof EvalError) fields.error_name = 'EvalError';
    else if (error instanceof Error) fields.error_name = 'Error';
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    const code = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    if (typeof code === 'string' && Object.hasOwn(ERROR_CODES, code)) fields.error_code = code;
    return fields;
  } catch {
    return {};
  }
}

function emit(level: LogLevel, event: EventName, fields: Record<string, string | number | undefined> = {}): void {
  if (typeof level !== 'string' || !Object.hasOwn(LEVELS, level)) return;
  const safeEvent: EventName = typeof event === 'string' && Object.hasOwn(EVENTS, event) ? event : 'unlisted_event';
  const line: Record<string, string | number> = {
    ts: new Date().toISOString(),
    level,
    event: safeEvent,
    request_id: requestContext.getStore()?.requestId ?? 'startup',
  };
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) line[key] = value;
  }
  process.stdout.write(`${JSON.stringify(line)}\n`);
}

export function log(level: LogLevel, event: EventName, errorCode?: string): void {
  const safeCode = typeof errorCode === 'string' && Object.hasOwn(ERROR_CODES, errorCode) ? errorCode : undefined;
  emit(level, event, { error_code: safeCode });
}

/** Event with numeric fields only (status, count): never ids, addresses or tokens. */
export function logMetric(
  level: 'info' | 'warn' | 'error',
  event: EventName,
  fields: { status?: number; count?: number },
): void {
  emit(level, event, { status: fields.status, count: fields.count });
}

export function logError(level: 'warn' | 'error', event: EventName, error: unknown): void {
  emit(level, event, safeErrorFields(error));
}

export function betterAuthLog(level: LogLevel, _message: string, ...args: unknown[]): void {
  const error = args.find((arg) => arg instanceof Error);
  if (error && (level === 'error' || level === 'warn')) logError(level, 'better_auth', error);
  else log(level, 'better_auth');
}

export function withScheduledLogContext<T>(operation: () => T): T {
  return requestContext.run({ requestId: 'scheduled' }, operation);
}

function thirdPartyConsole(level: LogLevel, args: unknown[]): void {
  const error = args.find((arg) => arg instanceof Error);
  emit(level, 'third_party_console', safeErrorFields(error));
}

const NO_OUTPUT_CONSOLE_METHODS = new Set(['constructor', 'Console']);
const consoleMethods = new Set<string>();
let consolePrototype: object | null = console;
while (consolePrototype && consolePrototype !== Object.prototype) {
  for (const method of Object.getOwnPropertyNames(consolePrototype)) {
    if (NO_OUTPUT_CONSOLE_METHODS.has(method) || consoleMethods.has(method)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(consolePrototype, method);
    if (typeof descriptor?.value === 'function') consoleMethods.add(method);
  }
  consolePrototype = Object.getPrototypeOf(consolePrototype) as object | null;
}
for (const method of consoleMethods) {
  const level: LogLevel = method === 'error' ? 'error' : method === 'warn' ? 'warn' :
    method === 'debug' || method === 'trace' ? 'debug' : 'info';
  (console as unknown as Record<string, (...args: unknown[]) => void>)[method] = (...args) => thirdPartyConsole(level, args);
}

export function logConfigInvalid(configKey: string): void {
  if (!Object.hasOwn(CONFIG_KEYS, configKey)) return;
  emit('error', 'config_invalid', { error_code: configKey });
}

function handleUncaughtException(error: Error): void {
  logError('error', 'uncaught_exception', error);
  process.exit(1);
}

function handleUnhandledRejection(reason: unknown): void {
  logError('error', 'unhandled_rejection', reason);
  process.exit(1);
}

export function installFatalHandlers(): void {
  process.on('uncaughtException', handleUncaughtException);
  process.on('unhandledRejection', handleUnhandledRejection);
}

function routeTemplate(route: string | undefined): string {
  return !route || route === '*' || route === '/*' ? '<unmatched>' : route;
}

export const requestLogger: MiddlewareHandler<ApiEnv> = async (c, next) => {
  const requestId = randomUUID();
  const startedAt = performance.now();
  c.set('requestId', requestId);
  c.header('X-Request-Id', requestId);
  await requestContext.run({ requestId }, async () => {
    await next();
    emit('info', 'request', {
      method: Object.hasOwn(METHODS, c.req.method) ? c.req.method : 'GET',
      route: routeTemplate(c.req.routePath),
      status: Number.isInteger(c.res.status) && c.res.status >= 100 && c.res.status <= 599 ? c.res.status : 500,
      ms: Math.max(0, Math.min(86_400_000, Math.round(performance.now() - startedAt))),
    });
  });
};

export const apiErrorHandler: ErrorHandler<ApiEnv> = (error, c) => {
  emit('error', 'api_error', {
    ...safeErrorFields(error),
    route: routeTemplate(c.req.routePath),
  });
  return c.json({ error: 'Internal server error' }, 500);
};
