import type { Context, MiddlewareHandler } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { ADMIN_MANAGED_SCOPES, TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { isNativeDelegationClient } from './policy';
import { NATIVE_DELEGATION_ENDPOINT_PATHS } from './public-protocol';
import { storedOpaqueAccessToken, storedRefreshToken, storedToken, type ProviderTokenOptions } from './provider-tokens';
import { authoritativeQuery, matchesAuthoritativeQuery } from './par';
import { nativeUserRetryAfter } from './user-rate-limit';

/**
 * Fail-closed guards in front of better-auth's OAuth provider (spec:
 * "Provider refresh and revoke interception").
 *
 * - Authorize: `tinycloud:delegation` is never requested on the authorize
 *   URL, and a delegation client may not omit `scope`, because the provider
 *   would default to the client's scopes.
 * - Token, `grant_type=refresh_token`: refused for a native token and for a
 *   native-capable client.
 * - Token, any other grant: a `resource` parameter is refused for a
 *   native-capable client, so the provider never issues it a JWT access
 *   token. Like any failed exchange, the refusal spends the authorization
 *   code, but only a code issued to the client presenting it.
 * - Revoke: refused for a `Bearer `-prefixed token; for a native-capable
 *   client, anything but its own access token; a native refresh token; and a
 *   token issued to another client (plan amendment A2). No side effects. An
 *   unknown token otherwise gets RFC 7009's 200 once the provider has
 *   validated the client, JWT-shaped or not.
 * - Client create/update: the admin-managed scopes (`tinycloud:delegation`,
 *   `tinycloud:manage-key`) are never added or removed through the
 *   provider's user-facing client routes.
 *
 * Native tokens are classified by how they were issued, never by the
 * client's current configuration. Tokens are normalized with the provider's
 * own options before every lookup, and bodies are parsed the way the provider
 * parses them; duplicate parameters are refused rather than resolved.
 */

const AUTH_BASE_PATH = '/api/auth';
const FORM_MEDIA_TYPE = 'application/x-www-form-urlencoded';
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export type ProviderInterceptorDatabase = Pick<PrismaClient, 'oauthClient' | 'oauthRefreshToken' | 'oauthAccessToken' | 'tinyCloudNativeGrant' | 'tinyCloudNativeRequest'>;

type Refusal = { status: 400 | 401 | 429; error: string; description: string; retryAfter?: number };
/**
 * Send this request to the provider instead, then answer RFC 7009's 200 if
 * it reports the token unknown.
 */
type UnknownToken = { unknownToken: Request };
type Decision = Refusal | null | UnknownToken | { replacement: Request } | { redirect: string };
const JSON_MEDIA_TYPE = /^application\/([a-z0-9.+-]*\+)?json/i;
type ParsedBody = { params: URLSearchParams } | { refusal: Refusal } | { passThrough: true };

/** The route better-call dispatches on: everything after the first base path. */
function providerPath(url: string): string | null {
  const pathname = new URL(url).pathname;
  const index = pathname.indexOf(AUTH_BASE_PATH);
  if (index < 0) return null;
  return pathname.slice(index + AUTH_BASE_PATH.length).replace(/\/+$/, '');
}

function refuse(c: Context, refusal: Refusal): Response {
  return c.json({ error: refusal.error, error_description: refusal.description }, refusal.status, {
    'Cache-Control': 'no-store',
    ...(refusal.retryAfter ? { 'Retry-After': String(refusal.retryAfter) } : {}),
  });
}

function duplicateKey(params: URLSearchParams): string | undefined {
  const seen = new Set<string>();
  for (const key of params.keys()) {
    if (seen.has(key)) return key;
    seen.add(key);
  }
  return undefined;
}

function scopeList(scope: string | null): string[] {
  return (scope ?? '').split(' ').filter(Boolean);
}

/**
 * The JSON body better-call hands the client routes. Their schemas need
 * arrays and objects, which only JSON can carry, so any other body fails the
 * provider's validation and passes through untouched.
 */
async function parseProviderJson(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.body || !JSON_MEDIA_TYPE.test((request.headers.get('content-type') ?? '').toLowerCase())) return null;
  try {
    const body: unknown = JSON.parse(await request.clone().text());
    return body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    // The provider's own parse fails the same way, before any write.
    return null;
  }
}

const adminManagedScope: Refusal = {
  status: 400,
  error: 'invalid_scope',
  description: `${[...ADMIN_MANAGED_SCOPES].join(' and ')} are granted only by OpenKey admins`,
};

function mentionsAdminManagedScope(scope: unknown): boolean {
  return typeof scope === 'string' && scopeList(scope).some((entry) => ADMIN_MANAGED_SCOPES.has(entry));
}

/**
 * better-call accepts a body when the media type contains the form type and
 * then parses it as JSON, form or text depending on further substrings. Only
 * the exact form type is parsed here. Anything else the provider would accept
 * is refused; anything it rejects (415, missing body) passes through.
 */
async function parseProviderForm(request: Request): Promise<ParsedBody> {
  if (!request.body) return { passThrough: true };
  const mediaType = (request.headers.get('content-type') ?? '').toLowerCase().split(';')[0]!.trim();
  if (mediaType !== FORM_MEDIA_TYPE) {
    return mediaType.includes(FORM_MEDIA_TYPE)
      ? { refusal: { status: 400, error: 'invalid_request', description: `Content-Type must be ${FORM_MEDIA_TYPE}` } }
      : { passThrough: true };
  }
  const params = new URLSearchParams(await request.clone().text());
  const duplicate = duplicateKey(params);
  if (duplicate) {
    return { refusal: { status: 400, error: 'invalid_request', description: `parameter ${duplicate} is repeated` } };
  }
  return { params };
}

/**
 * Client identity as the provider resolves it: a Basic header, when present,
 * replaces the body credentials. Only canonical base64 is accepted so this
 * decoder and the provider's always agree on the client_id.
 */
function requestClients(request: Request, params: URLSearchParams): { effective: string | null; candidates: string[] } | Refusal {
  const authorization = request.headers.get('authorization');
  const bodyClient = params.get('client_id');
  if (!authorization?.startsWith('Basic ')) {
    return { effective: bodyClient, candidates: bodyClient ? [bodyClient] : [] };
  }
  const encoded = authorization.slice('Basic '.length);
  const invalid: Refusal = { status: 401, error: 'invalid_client', description: 'invalid authorization header format' };
  if (!CANONICAL_BASE64.test(encoded)) return invalid;
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  const separator = decoded.indexOf(':');
  if (separator <= 0 || separator === decoded.length - 1) return invalid;
  const basicClient = decoded.slice(0, separator);
  return { effective: basicClient, candidates: [...new Set([basicClient, ...(bodyClient ? [bodyClient] : [])])] };
}

export interface ProviderInterceptorOptions {
  database: ProviderInterceptorDatabase;
  /** The provider plugin's configured options; see `providerTokenOptions`. */
  tokens: ProviderTokenOptions;
  /** better-auth's request handler, for an unknown token's rewritten revoke. */
  provider: (request: Request) => Response | Promise<Response>;
  getSessionUserId: (headers: Headers) => Promise<string | null>;
  /**
   * better-auth's verification storage, where the provider keeps
   * authorization codes: `internalAdapter.findVerificationValue` and
   * `deleteVerificationByIdentifier`, called with the stored code value.
   */
  authorizationCodes: {
    find: (identifier: string) => Promise<{ value: string } | null>;
    delete: (identifier: string) => Promise<void>;
  };
}

type RefreshTokenMatch = { clientId: string; native: boolean };
type AccessTokenMatch = { clientId: string };

export function createProviderInterceptors({ database, tokens, provider, getSessionUserId, authorizationCodes }: ProviderInterceptorOptions): MiddlewareHandler {
  async function anyDelegationClient(clientIds: string[]): Promise<boolean> {
    if (clientIds.length === 0) return false;
    const clients = await database.oauthClient.findMany({
      where: { clientId: { in: clientIds } },
      select: { scopes: true, tinycloudNativeDelegation: true },
    });
    return clients.some(isNativeDelegationClient);
  }

  /**
   * Native-capable: delegation is enabled now, or the client has ever issued
   * a native grant (any status). Grant rows only disappear with the client or
   * user, so disabling delegation never reopens the provider's refresh and
   * revoke paths for the client. Any client id the request names counts.
   */
  async function anyNativeCapableClient(clientIds: string[]): Promise<boolean> {
    if (clientIds.length === 0) return false;
    const [enabled, grant] = await Promise.all([
      anyDelegationClient(clientIds),
      database.tinyCloudNativeGrant.findFirst({ where: { clientId: { in: clientIds } }, select: { id: true } }),
    ]);
    return enabled || grant !== null;
  }

  /**
   * A stored refresh-token value, classified by how it was issued: native if
   * its row (revoked or not) carries tinycloud:delegation, or if it is a
   * native grant's current or previous hash, whatever the grant's status.
   */
  async function refreshTokenByStoredValue(stored: string): Promise<RefreshTokenMatch | null> {
    const [row, grant] = await Promise.all([
      database.oauthRefreshToken.findUnique({ where: { token: stored }, select: { clientId: true, scopes: true } }),
      database.tinyCloudNativeGrant.findFirst({
        where: { OR: [{ refreshTokenHash: stored }, { previousRefreshTokenHash: stored }] },
        select: { clientId: true },
      }),
    ]);
    if (!row && !grant) return null;
    return {
      clientId: row?.clientId ?? grant!.clientId,
      native: Boolean(grant) || row!.scopes.includes(TINYCLOUD_DELEGATION_SCOPE),
    };
  }

  async function refreshToken(token: string): Promise<RefreshTokenMatch | null> {
    const stored = await storedRefreshToken(tokens, token);
    return stored === null ? null : refreshTokenByStoredValue(stored);
  }

  /**
   * An opaque access token's owner. Revocation decides on ownership alone:
   * a native-capable client's own access tokens pass, native or not, and the
   * provider deletes only that row.
   */
  async function accessToken(token: string): Promise<AccessTokenMatch | null> {
    const stored = await storedOpaqueAccessToken(tokens, token);
    if (stored === null) return null;
    return database.oauthAccessToken.findUnique({ where: { token: stored }, select: { clientId: true } });
  }

  /**
   * Spends an authorization code the way the provider's exchange does
   * (find, then delete by the stored value), but only when the code was
   * issued to `clientId`: a code presented by any other client stays
   * redeemable by its own client. A value that does not parse as an
   * authorization code is not this client's, and is left alone.
   */
  async function spendOwnAuthorizationCode(code: string | null, clientId: string | null): Promise<void> {
    if (!code || !clientId) return;
    const identifier = await storedToken(tokens, code, 'authorization_code');
    const verification = await authorizationCodes.find(identifier);
    if (!verification) return;
    let value: { type?: unknown; query?: { client_id?: unknown } } | null;
    try {
      value = JSON.parse(verification.value) as typeof value;
    } catch {
      return;
    }
    if (value?.type !== 'authorization_code' || value.query?.client_id !== clientId) return;
    await authorizationCodes.delete(identifier);
  }

  async function guardAuthorize(c: Context): Promise<Decision> {
    const params = new URL(c.req.url).searchParams;
    const duplicate = duplicateKey(params);
    const invalid = (): Decision => ({ redirect: `${AUTH_BASE_PATH}/error?error=invalid_request` });
    if (duplicate) return invalid();
    const requestId = params.get('tinycloud_request');
    if (params.has('tinycloud_request')) {
      if (params.has('request_uri')) return invalid();
      if (!requestId) return invalid();
      const row = await database.tinyCloudNativeRequest.findUnique({ where: { id: requestId } });
      if (!row || row.status !== 'RESOLVED' || row.expiresAt <= new Date()) return invalid();
      const expected = authoritativeQuery(row);
      if (!matchesAuthoritativeQuery(params, expected)) return invalid();
      const userId = await getSessionUserId(c.req.raw.headers);
      if (userId) {
        const retryAfter = nativeUserRetryAfter(userId, 'authorize');
        if (retryAfter) return { status: 429, error: 'slow_down', description: 'too many authorization requests', retryAfter };
      }
      const url = new URL(c.req.url);
      url.search = expected.toString();
      return { replacement: new Request(url, c.req.raw) };
    }
    if (scopeList(params.get('scope')).includes(TINYCLOUD_DELEGATION_SCOPE)) {
      if (!params.has('request_uri')) return invalid();
    }
    const clientId = params.get('client_id');
    if (!params.has('scope') && !params.has('request_uri') && clientId && await anyDelegationClient([clientId])) {
      return invalid();
    }
    return null;
  }

  async function guardToken(c: Context): Promise<Refusal | null> {
    const parsed = await parseProviderForm(c.req.raw);
    if ('passThrough' in parsed) return null;
    if ('refusal' in parsed) return parsed.refusal;
    const { params } = parsed;
    const grantType = params.get('grant_type');
    if (grantType !== 'refresh_token' && !params.has('resource')) return null;
    const clients = requestClients(c.req.raw, params);
    if ('status' in clients) return clients;
    if (grantType !== 'refresh_token') {
      // A `resource` makes the provider issue a JWT access token, which has
      // no token row: consent withdrawal could not revoke it. A native-capable
      // client only ever receives opaque, row-backed access tokens.
      if (!await anyNativeCapableClient(clients.candidates)) return null;
      // Any failed exchange spends the code (spec "Code exchange and token
      // response"), this refusal included.
      if (grantType === 'authorization_code') await spendOwnAuthorizationCode(params.get('code'), clients.effective);
      return {
        status: 400,
        error: 'invalid_request',
        description: 'resource is not supported for native delegation clients',
      };
    }
    // The refresh grant decodes the token without stripping `Bearer `.
    const token = params.get('refresh_token');
    const presented = token ? await refreshToken(token) : null;
    // A native token never reaches the provider, whatever the client's
    // current configuration or the requested scope. A native-capable client
    // never refreshes through the provider either: a revoked token of that
    // client, even an ordinary one, would otherwise delete every refresh
    // token, native ones included, that the user holds for it.
    if (presented?.native || await anyNativeCapableClient(clients.candidates)) {
      return {
        status: 400,
        error: 'invalid_grant',
        description: 'use the renew endpoint',
      };
    }
    return null;
  }

  /** Spec "Provider refresh and revoke interception", revoke table; first match applies. */
  async function guardRevoke(c: Context): Promise<Decision> {
    const parsed = await parseProviderForm(c.req.raw);
    if ('passThrough' in parsed) return null;
    if ('refusal' in parsed) return parsed.refusal;
    const { params } = parsed;
    const token = params.get('token');
    if (token?.startsWith('Bearer ')) {
      return { status: 400, error: 'invalid_request', description: 'token must not carry a Bearer prefix' };
    }
    const clients = requestClients(c.req.raw, params);
    if ('status' in clients) return clients;
    if (!token) return null;
    // Looked up as both kinds, whatever token_type_hint says.
    const [refresh, access] = await Promise.all([refreshToken(token), accessToken(token)]);
    const unsupported: Refusal = {
      status: 400,
      error: 'unsupported_token_type',
      description: `revoke TinyCloud delegation sessions at ${AUTH_BASE_PATH}${NATIVE_DELEGATION_ENDPOINT_PATHS.revoke}`,
    };
    // A native-capable client reaches the provider only to revoke one of its
    // own access tokens. Everything else, unknown tokens and its own ordinary
    // refresh tokens included, could reach the provider's revoked-token
    // branch and delete the client's native refresh tokens.
    if (await anyNativeCapableClient(clients.candidates)) {
      return access && !refresh && access.clientId === clients.effective ? null : unsupported;
    }
    if (refresh?.native) return unsupported;
    const owner = refresh?.clientId ?? access?.clientId;
    if (owner === undefined) return { unknownToken: unknownTokenRevoke(c.req.raw, params) };
    if (owner !== clients.effective) {
      return { status: 400, error: 'invalid_request', description: 'token was not issued to this client' };
    }
    return null;
  }

  async function guardCreateClient(c: Context): Promise<Decision> {
    const body = await parseProviderJson(c.req.raw);
    return body && mentionsAdminManagedScope(body.scope) ? adminManagedScope : null;
  }

  // Better Auth's social callback can call authorizeEndpoint directly with
  // additionalData.query, bypassing this interceptor's authorize guard.
  // O4 MUST treat a code's stored provider query as untrusted and atomically
  // bind redemption to an APPROVED native request; this guard is defense in
  // depth, not evidence that every provider-internal path ran guardAuthorize.
  async function guardSocialSignIn(c: Context): Promise<Decision> {
    const body = await parseProviderJson(c.req.raw);
    const data = body?.additionalData;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
    const query = (data as Record<string, unknown>).query;
    if (query === undefined) return null;
    const invalid: Refusal = { status: 400, error: 'invalid_request', description: 'native delegation requires a pushed authorization request' };
    // Better Auth can normalize list-shaped query values after this hook.
    // Only a scalar query string has unambiguous scope and client identity.
    if (typeof query !== 'string') return invalid;
    const params = new URLSearchParams(query);
    const clientId = params.get('client_id');
    if (duplicateKey(params) || params.has('tinycloud_request') || params.has('request_uri') ||
      scopeList(params.get('scope')).includes(TINYCLOUD_DELEGATION_SCOPE) ||
      (!params.has('scope') && clientId && await anyDelegationClient([clientId]))) {
      return invalid;
    }
    return null;
  }

  /** Neither adds an admin-managed scope nor changes the scopes of a client holding one. */
  async function guardUpdateClient(c: Context): Promise<Decision> {
    const body = await parseProviderJson(c.req.raw);
    const update = body?.update;
    if (!update || typeof update !== 'object' || Array.isArray(update) || !('scope' in update)) return null;
    const scope = (update as Record<string, unknown>).scope;
    if (mentionsAdminManagedScope(scope)) return adminManagedScope;
    if (typeof body.client_id !== 'string') return null;
    const existing = await database.oauthClient.findUnique({ where: { clientId: body.client_id }, select: { scopes: true } });
    return existing?.scopes.some((entry) => ADMIN_MANAGED_SCOPES.has(entry)) ? adminManagedScope : null;
  }

  /**
   * The revoke the provider sees for a token no table holds. Forcing
   * `token_type_hint=refresh_token` skips the provider's JWT branch, which
   * throws a 500 for an unverifiable JWT-shaped token (`Missing jwt kid`, a
   * foreign algorithm). Nothing is lost: a JWT access token is never stored,
   * so the provider's revocation of one is a no-op. The provider still
   * validates the client and looks the token up, so client errors and server
   * errors (a failed database read) keep their own status.
   */
  function unknownTokenRevoke(request: Request, params: URLSearchParams): Request {
    const body = new URLSearchParams(params);
    body.set('token_type_hint', 'refresh_token');
    const headers = new Headers(request.headers);
    headers.delete('content-length');
    return new Request(request.url, { method: 'POST', headers, body: body.toString() });
  }

  /**
   * RFC 7009 §2.2: an unknown or invalid token is not an error. Only the
   * provider's unknown-refresh-token answers become 200: 400
   * `invalid_request` "token not found", or 400 `invalid_token` when a
   * configured refresh-token prefix is missing. Client errors (401/400
   * `invalid_client`) and every 5xx stay as they are.
   */
  async function answerUnknownToken(c: Context): Promise<void> {
    if (c.res.status !== 400) return;
    const body = await c.res.clone().json().catch(() => null) as { error?: unknown } | null;
    if (body?.error !== 'invalid_request' && body?.error !== 'invalid_token') return;
    const headers = new Headers(c.res.headers);
    headers.delete('content-length');
    c.res = new Response(null, { status: 200, headers });
  }

  // Other auth routes go straight to better-auth without an async hop.
  return (c, next) => {
    const path = providerPath(c.req.url);
    const post = c.req.method === 'POST';
    const guard: ((c: Context) => Promise<Decision>) | null = path === '/oauth2/authorize' ? guardAuthorize
      : post && path === '/sign-in/social' ? guardSocialSignIn
      : post && path === '/oauth2/token' ? guardToken
        : post && path === '/oauth2/revoke' ? guardRevoke
          : post && path === '/oauth2/create-client' ? guardCreateClient
            : post && path === '/oauth2/update-client' ? guardUpdateClient
              : null;
    if (!guard) return next();
    return guard(c).then(async (decision) => {
      if (decision && 'redirect' in decision) return c.redirect(decision.redirect, 302);
      if (decision && 'replacement' in decision) return provider(decision.replacement);
      if (decision && 'unknownToken' in decision) {
        c.res = await provider(decision.unknownToken);
        await answerUnknownToken(c);
        return c.res;
      }
      if (decision) return refuse(c, decision);
      await next();
    });
  };
}
