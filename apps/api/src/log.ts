import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { ErrorHandler, MiddlewareHandler } from 'hono';
import { TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS } from './services/tinycloud-hosts';

export type ApiEnv = { Variables: { requestId: string } };
type LogLevel = 'debug' | 'info' | 'warn' | 'error';
type ErrorFields = { error_name?: string; error_code?: string };
type RequestContext = { requestId: string };

const requestContext = new AsyncLocalStorage<RequestContext>();
const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function configuredOriginMatches(origin: string, host: string | undefined): boolean {
  if (!host) return false;
  try { return new URL(host).origin === origin; }
  catch { return false; }
}

// The pinned node SDK captures global fetch and has no transport hook for
// sign-in/hosting. Install before dependencies, like the console boundary below.
// Resolve context per call: cached SDK clients must not retain a prior request ID.
const originalFetch = globalThis.fetch;
globalThis.fetch = Object.assign(function fetchWithRequestId(input: Parameters<typeof fetch>[0], init?: RequestInit) {
  const requestId = requestContext.getStore()?.requestId;
  if (!requestId || !REQUEST_ID.test(requestId)) return originalFetch(input, init);
  let origin: string;
  try {
    origin = new URL(input instanceof Request ? input.url : input).origin;
  } catch {
    return originalFetch(input, init);
  }
  if (!TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(origin) &&
      !configuredOriginMatches(origin, process.env.TINYCLOUD_URL) &&
      !configuredOriginMatches(origin, process.env.TINYCLOUD_BOOTSTRAP_HOST)) {
    return originalFetch(input, init);
  }
  const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
  headers.set('X-Request-Id', requestId);
  // Native auto-follow carries custom headers across origins. Fail closed
  // rather than replay signed requests; explicit manual/error modes still work.
  const redirect = init?.redirect ?? (input instanceof Request ? input.redirect : 'follow');
  return originalFetch(input, { ...init, headers, redirect: redirect === 'follow' ? 'error' : redirect });
}, originalFetch);

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
  session_cap_unapplied: true,
  tinycloud_bootstrap_background_failed: true, tinycloud_bootstrap_background_completed: true,
  tinycloud_bootstrap_sweep_tick: true, tinycloud_bootstrap_sweep_healed: true,
  tinycloud_bootstrap_sweep_still_failed: true, tinycloud_bootstrap_sweep_exhausted: true,
  tinycloud_bootstrap_sweep_failed: true,
  tinycloud_bootstrap_space_registry_completed: true, native_par_valid_request_volume_threshold_reached: true,
  native_par_request_cleanup_failed: true, native_session_proof_cleanup_failed: true,
  scoreboard_protocol_users_call: true, app_sign_in_record_failed: true, permission_entry_unknown_field: true,
  third_party_console: true, uncaught_exception: true, unhandled_rejection: true, config_invalid: true,
  unlisted_event: true,
} as const satisfies Record<string, true>;
type EventName = keyof typeof EVENTS;
const CONFIG_KEYS: Record<string, true> = { BETTER_AUTH_URL: true };
const ERROR_CODES: Record<string, true> = {
  P2002: true, P2025: true, P2010: true, P2034: true, tinycloud_bootstrap_failed: true,
  tinycloud_bootstrap_crashed: true, tinycloud_bootstrap_in_progress: true,
  tinycloud_bootstrap_node_timeout: true, tinycloud_bootstrap_space_not_hosted: true,
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

function emit(level: LogLevel, event: EventName, fields: Record<string, string | number | boolean | undefined> = {}): void {
  if (typeof level !== 'string' || !Object.hasOwn(LEVELS, level)) return;
  const safeEvent: EventName = typeof event === 'string' && Object.hasOwn(EVENTS, event) ? event : 'unlisted_event';
  const line: Record<string, string | number | boolean> = {
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

const PERMISSION_FIELD_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
/** Distinct valid field names logged per request; further names are counted into one `other` line. */
const PERMISSION_FIELD_NAME_CAP = 8;

/**
 * Logs the dropped `permissions[]` entry fields of one request, given each distinct field name with
 * how many entries carried it. Field names only, never values. Per request: up to 8 valid names
 * (first seen first), one `[invalid]` line for all non-conforming names (`count` = entries carrying
 * them), and one `other` line whose `count` is the number of distinct valid names beyond the cap.
 */
export function logPermissionEntryUnknownFields(counts: ReadonlyMap<string, number>): void {
  let logged = 0;
  let overflow = 0;
  let invalid = 0;
  for (const [field, count] of counts) {
    if (!PERMISSION_FIELD_NAME.test(field)) {
      invalid += count;
    } else if (logged < PERMISSION_FIELD_NAME_CAP) {
      logged += 1;
      emit('info', 'permission_entry_unknown_field', { field, count });
    } else {
      overflow += 1;
    }
  }
  if (invalid > 0) emit('info', 'permission_entry_unknown_field', { field: '[invalid]', count: invalid });
  if (overflow > 0) emit('info', 'permission_entry_unknown_field', { field: 'other', count: overflow });
}

export type RequestedSpaceHosted = 'yes' | 'no' | 'timeout';

/**
 * Outcome of a TinyCloud bootstrap run that finished after (or apart from) the response: which
 * attempt it was, how long that attempt took, and whether the approval's requested space was
 * hosted before the response. Numbers, a closed string set and allow-listed codes only.
 */
export function logTinyCloudBootstrapBackground(
  event: 'tinycloud_bootstrap_background_failed' | 'tinycloud_bootstrap_background_completed',
  fields: { errorCode?: string; durationMs: number; attempt: number; requestedSpaceHosted?: RequestedSpaceHosted },
): void {
  emit(event === 'tinycloud_bootstrap_background_failed' ? 'error' : 'info', event, {
    error_code: typeof fields.errorCode === 'string' && Object.hasOwn(ERROR_CODES, fields.errorCode) ? fields.errorCode : undefined,
    duration_ms: Number.isFinite(fields.durationMs) ? Math.max(0, Math.round(fields.durationMs)) : undefined,
    attempt: fields.attempt,
    requested_space_hosted: fields.requestedSpaceHosted,
  });
}

export type TinyCloudBootstrapSweepEvent =
  | 'tinycloud_bootstrap_sweep_tick'
  | 'tinycloud_bootstrap_sweep_healed'
  | 'tinycloud_bootstrap_sweep_still_failed'
  | 'tinycloud_bootstrap_sweep_exhausted';

/**
 * Background sweep outcome: counts, attempt numbers, durations and allow-listed codes only. Never a
 * row id, user, key, address, host, failure message or sealed material.
 */
export function logTinyCloudBootstrapSweep(
  event: TinyCloudBootstrapSweepEvent,
  fields: {
    errorCode?: string;
    durationMs?: number;
    sweepAttempt?: number;
    candidates?: number;
    claimed?: number;
    healed?: number;
    stillFailed?: number;
    skipped?: number;
  },
): void {
  const level: LogLevel =
    event === 'tinycloud_bootstrap_sweep_exhausted' ? 'error'
    : event === 'tinycloud_bootstrap_sweep_still_failed' ? 'warn'
    : 'info';
  emit(level, event, {
    error_code: typeof fields.errorCode === 'string' && Object.hasOwn(ERROR_CODES, fields.errorCode) ? fields.errorCode : undefined,
    duration_ms: fields.durationMs !== undefined && Number.isFinite(fields.durationMs) ? Math.max(0, Math.round(fields.durationMs)) : undefined,
    sweep_attempt: fields.sweepAttempt,
    candidates: fields.candidates,
    claimed: fields.claimed,
    healed: fields.healed,
    still_failed: fields.stillFailed,
    skipped: fields.skipped,
  });
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
  const incoming = c.req.header('X-Request-Id');
  const validIncoming = incoming !== undefined && REQUEST_ID.test(incoming);
  const requestId = validIncoming ? incoming.toLowerCase() : randomUUID();
  const startedAt = performance.now();
  c.set('requestId', requestId);
  c.header('X-Request-Id', requestId);
  await requestContext.run({ requestId }, async () => {
    await next();
    emit('info', 'request', {
      request_id_replaced: incoming !== undefined && !validIncoming,
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
