import { createHash } from 'node:crypto';
import type { Context, MiddlewareHandler } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { isNativeDelegationClient } from './policy';
import { NATIVE_DELEGATION_ENDPOINT_PATHS } from './public-protocol';

/**
 * Fail-closed guards in front of better-auth's OAuth provider (TC-773 §1.3).
 *
 * - Authorize: `tinycloud:delegation` is never requested on the authorize
 *   URL (PAR is the only entry point), and a delegation client may not omit
 *   `scope`, because the provider would default to the client's scopes.
 * - Token, `grant_type=refresh_token`: refused for a delegation client's
 *   token, including revoked rows and rotated grant hashes. The provider's
 *   revoked-token branch would otherwise delete every refresh token the user
 *   holds for the client.
 * - Revoke: a refresh token is refused unless it was issued to the
 *   requesting client (plan amendment A2), and a delegation client's refresh
 *   token is refused outright, with no side effects. Access tokens pass.
 *
 * Bodies are parsed the way the provider parses them; duplicate parameters
 * are refused rather than resolved, so both sides always see the same values.
 */

const AUTH_BASE_PATH = '/api/auth';
const FORM_MEDIA_TYPE = 'application/x-www-form-urlencoded';
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export type ProviderInterceptorDatabase = Pick<PrismaClient, 'oauthClient' | 'oauthRefreshToken' | 'tinyCloudNativeGrant'>;

type Refusal = { status: 400 | 401; error: string; description: string };
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

/** better-auth stores opaque tokens as base64url SHA-256 (`storeTokens: 'hashed'`). */
function storedTokenHash(token: string): string {
  return createHash('sha256').update(token).digest('base64url');
}

export function createProviderInterceptors(database: ProviderInterceptorDatabase): MiddlewareHandler {
  async function anyDelegationClient(clientIds: string[]): Promise<boolean> {
    if (clientIds.length === 0) return false;
    const clients = await database.oauthClient.findMany({
      where: { clientId: { in: clientIds } },
      select: { scopes: true, tinycloudNativeDelegation: true },
    });
    return clients.some(isNativeDelegationClient);
  }

  /**
   * The presented refresh token's owner, from the provider's row (revoked rows
   * included) or a native grant's current or previous hash, and whether that
   * token belongs to a delegation client.
   */
  async function refreshTokenOwner(token: string): Promise<{ clientId: string; delegation: boolean } | null> {
    const hash = storedTokenHash(token);
    const [row, grant] = await Promise.all([
      database.oauthRefreshToken.findUnique({ where: { token: hash }, select: { clientId: true, scopes: true } }),
      database.tinyCloudNativeGrant.findFirst({
        where: { OR: [{ refreshTokenHash: hash }, { previousRefreshTokenHash: hash }] },
        select: { clientId: true },
      }),
    ]);
    if (!row && !grant) return null;
    const clientId = row?.clientId ?? grant!.clientId;
    const delegation = Boolean(grant) ||
      row!.scopes.includes(TINYCLOUD_DELEGATION_SCOPE) ||
      await anyDelegationClient([clientId]);
    return { clientId, delegation };
  }

  async function guardAuthorize(c: Context): Promise<Refusal | null> {
    const params = new URL(c.req.url).searchParams;
    const duplicate = duplicateKey(params);
    if (duplicate) return { status: 400, error: 'invalid_request', description: `parameter ${duplicate} is repeated` };
    if (scopeList(params.get('scope')).includes(TINYCLOUD_DELEGATION_SCOPE)) {
      return {
        status: 400,
        error: 'invalid_scope',
        description: `${TINYCLOUD_DELEGATION_SCOPE} is only available through pushed authorization requests`,
      };
    }
    const clientId = params.get('client_id');
    if (!params.has('scope') && !params.has('request_uri') && clientId && await anyDelegationClient([clientId])) {
      return { status: 400, error: 'invalid_scope', description: 'scope is required for this client' };
    }
    return null;
  }

  async function guardToken(c: Context): Promise<Refusal | null> {
    const parsed = await parseProviderForm(c.req.raw);
    if ('passThrough' in parsed) return null;
    if ('refusal' in parsed) return parsed.refusal;
    const { params } = parsed;
    if (params.get('grant_type') !== 'refresh_token') return null;
    const clients = requestClients(c.req.raw, params);
    if ('status' in clients) return clients;
    const token = params.get('refresh_token');
    const owner = token ? await refreshTokenOwner(token) : null;
    if (owner?.delegation || await anyDelegationClient(clients.candidates)) {
      return {
        status: 400,
        error: 'invalid_grant',
        description: `TinyCloud delegation sessions renew at ${AUTH_BASE_PATH}${NATIVE_DELEGATION_ENDPOINT_PATHS.renew}`,
      };
    }
    if (owner && owner.clientId !== clients.effective) {
      return { status: 400, error: 'invalid_grant', description: 'refresh token was not issued to this client' };
    }
    return null;
  }

  async function guardRevoke(c: Context): Promise<Refusal | null> {
    const parsed = await parseProviderForm(c.req.raw);
    if ('passThrough' in parsed) return null;
    if ('refusal' in parsed) return parsed.refusal;
    const { params } = parsed;
    const clients = requestClients(c.req.raw, params);
    if ('status' in clients) return clients;
    let token = params.get('token');
    if (token?.startsWith('Bearer ')) token = token.replace('Bearer ', '');
    if (!token) return null;
    const owner = await refreshTokenOwner(token);
    // Not a refresh token: the provider only deletes an access token issued
    // to the requesting client.
    if (!owner) return null;
    if (owner.clientId !== clients.effective) {
      return { status: 400, error: 'invalid_request', description: 'token was not issued to this client' };
    }
    if (owner.delegation || await anyDelegationClient(clients.candidates)) {
      return {
        status: 400,
        error: 'unsupported_token_type',
        description: `TinyCloud delegation sessions are revoked at ${AUTH_BASE_PATH}${NATIVE_DELEGATION_ENDPOINT_PATHS.revoke}`,
      };
    }
    return null;
  }

  // Other auth routes go straight to better-auth without an async hop.
  return (c, next) => {
    const path = providerPath(c.req.url);
    const guard = path === '/oauth2/authorize' ? guardAuthorize
      : path === '/oauth2/token' && c.req.method === 'POST' ? guardToken
        : path === '/oauth2/revoke' && c.req.method === 'POST' ? guardRevoke
          : null;
    if (!guard) return next();
    return guard(c).then(async (refusal) => {
      if (refusal) return refuse(c, refusal);
      await next();
    });
  };
}
