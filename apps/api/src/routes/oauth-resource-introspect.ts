// Token status check for registered resource servers (TC-1627).
//
// POST /api/oauth/resource/introspect, RFC 7662 shaped. The provider's stock
// /oauth2/introspect only answers for the client a token was issued to, and its
// answer for a JWT access token ignores consent withdrawal, sign-out and the
// like. This route is for a hosted resource (the TinyCloud MCP server) that
// holds a confidential client registered as a resource server: it may ask about
// tokens issued for its own resources, and it is told `active: true` only while
// the token's signature, audience, issuing client, user consent and session all
// still stand. Anything else is `{ "active": false }`, never an error.

import { Hono } from 'hono';
import type { JSONWebKeySet } from 'jose';
import type { PrismaClient } from '@openkey/db';
import { logError, logMetric } from '../log';
import { DEFAULT_RESOURCE_RATE_LIMIT_PER_MINUTE, clientSecretMatches, readResourceServerPolicy } from '../services/resource-server';
import { mcpTokenStatus } from '../services/mcp-token-status';
import { JWT_SHAPE, MAX_TOKEN_LENGTH, createAccessTokenVerifier } from '../services/access-token-verifier';
import { isAccessTokenRevoked } from '../services/revoked-access-token';

export type ResourceIntrospectDatabase = Pick<PrismaClient, 'oauthClient' | 'oauthConsent' | 'session' | 'revokedAccessToken'>;

export interface ResourceIntrospectLimits {
  /** Requests per window for an authenticated resource server whose registration sets no limit of its own. */
  authenticatedPerWindow: number;
  /** Failed client authentications per window for one source address. */
  failedAuthPerWindow: number;
  windowMs: number;
}

export const DEFAULT_RESOURCE_INTROSPECT_LIMITS: ResourceIntrospectLimits = {
  authenticatedPerWindow: DEFAULT_RESOURCE_RATE_LIMIT_PER_MINUTE,
  failedAuthPerWindow: 20,
  windowMs: 60_000,
};

export interface ResourceIntrospectOptions {
  prisma: ResourceIntrospectDatabase;
  /** The token issuer (`iss`), e.g. https://api.openkey.so/api/auth. */
  issuer: string;
  /** Audiences this server issues tokens for; a client's allowed resources are narrowed to these. */
  validAudiences: readonly string[];
  /** The issuer's public signing keys. */
  getJwks: () => Promise<JSONWebKeySet>;
  limits?: Partial<ResourceIntrospectLimits>;
  /** Clock, in milliseconds; tests only. */
  now?: () => number;
}

const MAX_BODY_BYTES = 16 * 1024;

const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' } as const;
const INACTIVE = { active: false } as const;

/** Fixed-window counters keyed by string; bounded so a flood of keys cannot grow it without limit. */
class FixedWindowCounter {
  private readonly windows = new Map<string, { start: number; count: number }>();
  constructor(private readonly windowMs: number, private readonly maxKeys = 10_000) {}

  private current(key: string, now: number): { start: number; count: number } | undefined {
    const entry = this.windows.get(key);
    if (entry && now - entry.start < this.windowMs) return entry;
    if (entry) this.windows.delete(key);
    return undefined;
  }

  /** Counts one event; false once the window's budget (`max`) is spent. */
  hit(key: string, now: number, max: number): boolean {
    const entry = this.current(key, now);
    if (entry) {
      entry.count += 1;
      return entry.count <= max;
    }
    if (this.windows.size >= this.maxKeys) {
      for (const [other, value] of this.windows) if (now - value.start >= this.windowMs) this.windows.delete(other);
      if (this.windows.size >= this.maxKeys) this.windows.delete(this.windows.keys().next().value as string);
    }
    this.windows.set(key, { start: now, count: 1 });
    return 1 <= max;
  }

  retryAfterSeconds(key: string, now: number): number {
    const entry = this.windows.get(key);
    return entry ? Math.max(1, Math.ceil((entry.start + this.windowMs - now) / 1000)) : 1;
  }
}

/**
 * The key for the failed-authentication limit. The API's only other per-address limit (device
 * authorization) reads the same two headers inline; there is no shared helper. They are the
 * caller's own address only if the API is reachable solely through Cloudflare, which sets
 * `cf-connecting-ip`. With neither header the key is the shared string `unknown`: that bucket
 * counts failed authentications only, so it can answer failing requests with 429 but never
 * blocks a client that presents valid credentials.
 */
function sourceAddress(headers: Headers): string {
  return headers.get('cf-connecting-ip') ?? headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
}

function formDecode(value: string): string | null {
  try { return decodeURIComponent(value.replace(/\+/g, '%20')); } catch { return null; }
}

/** RFC 6749 §2.3.1: the id and secret are form-urlencoded, joined by `:`, then base64. */
function basicCredentials(header: string | null): { id: string; secret: string } | null {
  if (!header || !/^basic\s/i.test(header)) return null;
  let decoded: string;
  try { decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8'); } catch { return null; }
  const separator = decoded.indexOf(':');
  if (separator <= 0) return null;
  const id = formDecode(decoded.slice(0, separator));
  const secret = formDecode(decoded.slice(separator + 1));
  return id && secret ? { id, secret } : null;
}

async function readCappedText(request: Request, maxBytes: number): Promise<{ text: string; truncated: boolean }> {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) return { text: '', truncated: true };
  const reader = request.body?.getReader();
  if (!reader) return { text: '', truncated: false };
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return { text: '', truncated: true };
    }
    chunks.push(value);
  }
  return { text: Buffer.concat(chunks).toString('utf8'), truncated: false };
}

interface ClientCredentials {
  id: string;
  secret: string;
}

/** The one credential set the request carries; null if it carries none or more than one kind. */
function requestCredentials(request: Request, form: URLSearchParams | null): ClientCredentials | null {
  const basic = basicCredentials(request.headers.get('authorization'));
  const hasBasic = /^basic\s/i.test(request.headers.get('authorization') ?? '');
  const ids = form?.getAll('client_id') ?? [];
  const secrets = form?.getAll('client_secret') ?? [];
  if (hasBasic) {
    if (!basic || secrets.length > 0 || ids.some((id) => id !== basic.id)) return null;
    return basic;
  }
  if (ids.length !== 1 || secrets.length !== 1 || !ids[0] || !secrets[0]) return null;
  return { id: ids[0], secret: secrets[0] };
}

export function createResourceIntrospectRouter(options: ResourceIntrospectOptions): Hono {
  const limits = { ...DEFAULT_RESOURCE_INTROSPECT_LIMITS, ...options.limits };
  const now = () => options.now?.() ?? Date.now();
  const authenticated = new FixedWindowCounter(limits.windowMs);
  const failedAuth = new FixedWindowCounter(limits.windowMs);
  const validAudiences = new Set(options.validAudiences);

  const verify = createAccessTokenVerifier({ issuer: options.issuer, getJwks: options.getJwks, now: options.now });

  async function status(allowedResources: string[], token: unknown) {
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH || !JWT_SHAPE.test(token)) return INACTIVE;
    const audience = allowedResources.filter((resource) => validAudiences.has(resource));
    if (audience.length === 0) return INACTIVE;
    const payload = await verify(token, audience);
    if (!payload) return INACTIVE;
    const { sub, azp, sid, scope, iat, exp, aud } = payload as Record<string, unknown>;
    if (typeof sub !== 'string' || typeof azp !== 'string' || typeof sid !== 'string' || typeof scope !== 'string' ||
      typeof iat !== 'number' || typeof exp !== 'number') return INACTIVE;
    const audiences = (Array.isArray(aud) ? aud : [aud]).filter((value): value is string => typeof value === 'string' && audience.includes(value));
    if (audiences.length === 0) return INACTIVE;

    // The connection must still stand (client, consent, scopes, consent age, session), and the token
    // must not have been revoked at /oauth2/revoke. The reads run together; a read that fails is
    // thrown to the route's 503: never `active: true` on an error.
    const [revoked, state] = await Promise.all([
      isAccessTokenRevoked(options.prisma, token),
      mcpTokenStatus(
        options.prisma,
        { userId: sub, clientId: azp, sessionId: sid, scopes: scope.split(' ').filter(Boolean), issuedAtSeconds: iat },
        new Date(now()),
      ),
    ]);
    if (revoked || !state.active) return INACTIVE;

    return {
      active: true,
      scope,
      client_id: azp,
      sub,
      // The token's audiences this server may check, as an array or a string like the token's own `aud`.
      aud: Array.isArray(aud) ? audiences : audiences[0]!,
      exp,
      iat,
      iss: options.issuer,
      token_type: 'Bearer',
    };
  }

  const router = new Hono();

  router.post('/', async (c) => {
    const at = now();
    const source = sourceAddress(c.req.raw.headers);
    try {
      const contentType = c.req.raw.headers.get('content-type')?.toLowerCase() ?? '';
      const body = await readCappedText(c.req.raw, MAX_BODY_BYTES);
      const form = !body.truncated && contentType.startsWith('application/x-www-form-urlencoded')
        ? new URLSearchParams(body.text)
        : null;
      const credentials = requestCredentials(c.req.raw, form);

      const client = credentials
        ? await options.prisma.oauthClient.findUnique({
            where: { clientId: credentials.id },
            select: { clientId: true, clientSecret: true, disabled: true, public: true, metadata: true },
          })
        : null;
      // The secret is compared even for an unknown client, so the answer takes the same time.
      const secretOk = clientSecretMatches(credentials?.secret ?? '', client?.clientSecret);
      const policy = client ? readResourceServerPolicy(client.metadata) : null;
      if (!credentials || !client || !secretOk || client.disabled || client.public || !policy) {
        if (!failedAuth.hit(source, at, limits.failedAuthPerWindow)) {
          logMetric('warn', 'resource_introspect_rate_limited', { status: 429 });
          return c.json({ error: 'too_many_requests' }, 429, { ...NO_STORE, 'Retry-After': String(failedAuth.retryAfterSeconds(source, at)) });
        }
        return c.json(
          { error_description: credentials ? 'invalid client credentials' : 'missing required credentials', error: 'invalid_client' },
          401,
          { ...NO_STORE, 'WWW-Authenticate': 'Basic realm="openkey-resource-introspect"' },
        );
      }

      if (!authenticated.hit(client.clientId, at, policy.rateLimitPerMinute ?? limits.authenticatedPerWindow)) {
        logMetric('warn', 'resource_introspect_rate_limited', { status: 429 });
        return c.json({ error: 'too_many_requests' }, 429, { ...NO_STORE, 'Retry-After': String(authenticated.retryAfterSeconds(client.clientId, at)) });
      }

      const tokens = form?.getAll('token') ?? [];
      return c.json(await status(policy.allowedResources, tokens.length === 1 ? tokens[0] : undefined), 200, NO_STORE);
    } catch (error) {
      logError('error', 'resource_introspect_failed', error);
      return c.json({ error: 'temporarily_unavailable' }, 503, NO_STORE);
    }
  });

  return router;
}
