import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { Hono, type MiddlewareHandler } from 'hono';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import type { SessionContext } from '../middleware/session';

// Codes are stored and looked up in lower case, the form every CLI since the
// broker shipped lower-cases to before its GET, so codes issued before codes
// were shown in upper case still redeem. Responses carry the upper-case form.
const CODE_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
// Five minutes, the same as the CLI's sign-in wait.
const CODE_TTL_MS = 5 * 60 * 1000;
const PUBLIC_DELEGATION_FIELDS: Record<string, true> = {
  delegationHeader: true,
  delegationCid: true,
  spaceId: true,
  ownerDid: true,
  verificationMethod: true,
  jwk: true,
  address: true,
  chainId: true,
  hostActivated: true,
  spaceReady: true,
  spaceError: true,
  spacePending: true,
  primary: true,
  edited: true,
  reason: true,
  expirationTime: true,
  expiresAt: true,
  expiry: true,
  siwe: true,
  signature: true,
  signedMessage: true,
  permissions: true,
};
const PUBLIC_JWK_FIELDS: Record<string, true> = { kty: true, crv: true, x: true, kid: true };
function isPublicDelegation(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const delegation = value as Record<string, unknown>;
  const headerValue = delegation.delegationHeader;
  const jwkValue = delegation.jwk;
  if (!headerValue || typeof headerValue !== 'object' || Array.isArray(headerValue)) return false;
  if (!jwkValue || typeof jwkValue !== 'object' || Array.isArray(jwkValue)) return false;
  const header = headerValue as Record<string, unknown>;
  const jwk = jwkValue as Record<string, unknown>;
  const serialized = JSON.stringify(delegation) ?? '';
  return Object.keys(delegation).every((field) => Object.hasOwn(PUBLIC_DELEGATION_FIELDS, field)) &&
    typeof header.Authorization === 'string' && !!header.Authorization &&
    Object.keys(header).every((field) => field === 'Authorization') &&
    typeof delegation.delegationCid === 'string' && !!delegation.delegationCid &&
    typeof delegation.spaceId === 'string' && !!delegation.spaceId &&
    typeof delegation.verificationMethod === 'string' && !!delegation.verificationMethod &&
    jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string' &&
    Object.keys(jwk).every((field) => Object.hasOwn(PUBLIC_JWK_FIELDS, field)) &&
    (delegation.primary === undefined || typeof delegation.primary === 'boolean') &&
    (delegation.spacePending === undefined || delegation.spacePending === true) &&
    serialized.length <= 128 * 1024;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`).join(',')}}`;
}

function delegationDigest(delegation: Record<string, unknown>): string {
  return createHash('sha256').update(stableStringify(delegation)).digest('base64url');
}

interface RefreshGrantClaims {
  userId: string;
  sessionId: string;
  expiresAt: number;
  delegationDigest: string;
}

function createRefreshGrant(input: {
  secret: string;
  userId: string;
  sessionId: string;
  expiresAt: Date;
  delegation: Record<string, unknown>;
}): string {
  const payload = Buffer.from(JSON.stringify({
    userId: input.userId,
    sessionId: input.sessionId,
    expiresAt: input.expiresAt.getTime(),
    delegationDigest: delegationDigest(input.delegation),
  } satisfies RefreshGrantClaims)).toString('base64url');
  const signature = createHmac('sha256', input.secret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function verifyRefreshGrant(input: {
  token: unknown;
  secret: string;
  userId: string;
  sessionId: string;
  sessionExpiresAt: Date;
  now: Date;
  delegation: Record<string, unknown>;
}): boolean {
  if (typeof input.token !== 'string') return false;
  const [payload, signature, extra] = input.token.split('.');
  if (!payload || !signature || extra !== undefined) return false;
  const expectedSignature = createHmac('sha256', input.secret).update(payload).digest();
  const receivedSignature = Buffer.from(signature, 'base64url');
  if (receivedSignature.length !== expectedSignature.length || !timingSafeEqual(receivedSignature, expectedSignature)) return false;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Partial<RefreshGrantClaims>;
    return claims.userId === input.userId &&
      claims.sessionId === input.sessionId &&
      typeof claims.expiresAt === 'number' &&
      claims.expiresAt <= input.sessionExpiresAt.getTime() &&
      claims.expiresAt > input.now.getTime() &&
      claims.delegationDigest === delegationDigest(input.delegation);
  } catch {
    return false;
  }
}

export interface DelegationCodeStore {
  create(code: string, delegation: unknown, expiresAt: Date): Promise<boolean>;
  // Removes the code and returns it. Must be atomic: at most one caller gets a record for a given code.
  consume(code: string): Promise<{ delegation: unknown; expiresAt: Date } | null>;
  deleteExpired(before: Date): Promise<void>;
}

const LOOKUP_LIMIT_PER_MINUTE = 60;
const LOOKUP_WINDOW_MS = 60 * 1000;

// Global cap on redeem attempts per minute.
function createGlobalLookupLimiter(now: () => Date) {
  let windowStart = 0;
  let count = 0;
  return (): number => {
    const current = now().getTime();
    if (current - windowStart >= LOOKUP_WINDOW_MS) {
      windowStart = current;
      count = 0;
    }
    if (count >= LOOKUP_LIMIT_PER_MINUTE) return Math.max(1, Math.ceil((windowStart + LOOKUP_WINDOW_MS - current) / 1000));
    count += 1;
    return 0;
  };
}

export function createDelegationCodeRouter(input: {
  store: DelegationCodeStore;
  now?: () => Date;
  sessionMiddleware: MiddlewareHandler<SessionContext>;
  refreshGrantSecret: string;
  isDelegationOwnedByUser: (userId: string, delegation: Record<string, unknown>) => Promise<boolean>;
}) {
  if (!input.refreshGrantSecret.trim()) throw new Error('Delegation-code refresh secret is required');
  const router = new Hono<SessionContext>();
  const now = input.now ?? (() => new Date());
  const takeLookupSlot = createGlobalLookupLimiter(now);
  async function issueCode(delegation: Record<string, unknown>) {
    const createdAt = now();
    const expiresAt = new Date(createdAt.getTime() + CODE_TTL_MS);
    await input.store.deleteExpired(createdAt);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const characters = randomBytes(8);
      const code = `${Array.from(characters.subarray(0, 4), (byte) => CODE_ALPHABET[byte & 31]).join('')}-${Array.from(characters.subarray(4), (byte) => CODE_ALPHABET[byte & 31]).join('')}`;
      if (await input.store.create(code, delegation, expiresAt)) {
        return { code: code.toUpperCase(), expiresAt: expiresAt.toISOString() };
      }
    }
    return null;
  }

  router.post('/', input.sessionMiddleware, async (c) => {
    const body: unknown = await c.req.json().catch(() => null);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return c.json({ error: 'Invalid public delegation' }, 400);
    }
    const delegation = (body as Record<string, unknown>).delegation;
    if (!isPublicDelegation(delegation)) return c.json({ error: 'Invalid public delegation' }, 400);
    if (!await input.isDelegationOwnedByUser(c.get('user').id, delegation)) {
      return c.json({ error: 'Delegation does not belong to this account' }, 403);
    }

    c.header('Cache-Control', 'no-store');
    const result = await issueCode(delegation);
    if (!result) return c.json({ error: 'Could not allocate delegation code' }, 503);
    const session = c.get('session');
    const refreshGrant = createRefreshGrant({
      secret: input.refreshGrantSecret,
      userId: c.get('user').id,
      sessionId: session.id,
      expiresAt: session.expiresAt,
      delegation,
    });
    return c.json({ ...result, refreshGrant }, 201);
  });

  router.post('/refresh', input.sessionMiddleware, async (c) => {
    const body: unknown = await c.req.json().catch(() => null);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return c.json({ error: 'Invalid refresh grant' }, 403);
    }
    const values = body as Record<string, unknown>;
    const delegation = values.delegation;
    if (!isPublicDelegation(delegation)) return c.json({ error: 'Invalid refresh grant' }, 403);
    const user = c.get('user');
    const session = c.get('session');
    if (!verifyRefreshGrant({
      token: values.refreshGrant,
      secret: input.refreshGrantSecret,
      userId: user.id,
      sessionId: session.id,
      sessionExpiresAt: session.expiresAt,
      now: now(),
      delegation,
    }) || !await input.isDelegationOwnedByUser(user.id, delegation)) {
      return c.json({ error: 'Invalid refresh grant' }, 403);
    }
    c.header('Cache-Control', 'no-store');
    const result = await issueCode(delegation);
    if (!result) return c.json({ error: 'Could not allocate delegation code' }, 503);
    return c.json(result, 201);
  });

  router.get('/:code', async (c) => {
    c.header('Cache-Control', 'no-store');
    const retryAfter = takeLookupSlot();
    if (retryAfter > 0) {
      c.header('Retry-After', String(retryAfter));
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }
    const code = c.req.param('code').toLowerCase();
    if (!/^[a-z2-7]{4}-[a-z2-7]{4}$/.test(code)) {
      return c.json({ error: 'Not found' }, 404);
    }
    // Redeeming removes the code: a second redeem, an expired code and an unknown code all get the same 404.
    const record = await input.store.consume(code);
    if (!record || record.expiresAt <= now()) {
      return c.json({ error: 'Not found' }, 404);
    }
    return c.json({ delegation: record.delegation });
  });

  return router;
}

export function createPrismaDelegationCodeStore(prisma: PrismaClient = createPrismaClient()): DelegationCodeStore {
  return {
    async create(code, delegation, expiresAt) {
      try {
        await prisma.delegationCode.create({ data: { code, delegation: delegation as object, expiresAt } });
        return true;
      } catch (error) {
        if (error && typeof error === 'object' && 'code' in error && error.code === 'P2002') return false;
        throw error;
      }
    },
    async consume(code) {
      try {
        return await prisma.delegationCode.delete({ where: { code }, select: { delegation: true, expiresAt: true } });
      } catch (error) {
        if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') return null;
        throw error;
      }
    },
    async deleteExpired(before) {
      await prisma.delegationCode.deleteMany({ where: { expiresAt: { lte: before } } });
    },
  };
}
