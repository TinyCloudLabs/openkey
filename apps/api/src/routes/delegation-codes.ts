import { randomBytes } from 'node:crypto';
import { Hono, type MiddlewareHandler } from 'hono';
import { createPrismaClient } from '@openkey/db';

// Codes are stored and looked up in lower case, the form every CLI since the
// broker shipped lower-cases to before its GET, so codes issued before codes
// were shown in upper case still redeem. Responses carry the upper-case form.
const CODE_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
// Five minutes: the CLI's browser-callback wait is also five minutes, and a person types a pasted code right after seeing it.
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

export interface DelegationCodeStore {
  create(code: string, delegation: unknown, expiresAt: Date): Promise<boolean>;
  // Removes the code and returns it. Must be atomic: at most one caller gets a record for a given code.
  consume(code: string): Promise<{ delegation: unknown; expiresAt: Date } | null>;
  deleteExpired(before: Date): Promise<void>;
}

const LOOKUP_LIMIT_PER_WINDOW = 30;
const LOOKUP_WINDOW_MS = 60 * 1000;
const LOOKUP_BUCKET_LIMIT = 10_000;

/** Fixed one-minute window per client address, bounded map. Returns seconds until retry, or 0 when the lookup may proceed. */
function createLookupLimiter(now: () => Date) {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  return (client: string): number => {
    const current = now().getTime();
    const prior = buckets.get(client);
    const bucket = prior && prior.resetAt > current ? prior : { count: 0, resetAt: current + LOOKUP_WINDOW_MS };
    if (bucket.count >= LOOKUP_LIMIT_PER_WINDOW) return Math.max(1, Math.ceil((bucket.resetAt - current) / 1000));
    bucket.count += 1;
    buckets.delete(client);
    buckets.set(client, bucket);
    if (buckets.size > LOOKUP_BUCKET_LIMIT) buckets.delete(buckets.keys().next().value!);
    return 0;
  };
}

export function createDelegationCodeRouter(input: {
  store: DelegationCodeStore;
  now?: () => Date;
  sessionMiddleware: MiddlewareHandler;
}) {
  const router = new Hono();
  const now = input.now ?? (() => new Date());
  const takeLookupSlot = createLookupLimiter(now);

  router.post('/', input.sessionMiddleware, async (c) => {
    const body = await c.req.json().catch(() => null);
    const delegation = body?.delegation;
    const jwk = delegation?.jwk;
    const serialized = JSON.stringify(delegation);
    if (
      !delegation || typeof delegation !== 'object' || Array.isArray(delegation) ||
      Object.keys(delegation).some((field) => !PUBLIC_DELEGATION_FIELDS[field]) ||
      typeof delegation.delegationHeader?.Authorization !== 'string' ||
      !delegation.delegationHeader.Authorization ||
      Object.keys(delegation.delegationHeader).some((field) => field !== 'Authorization') ||
      typeof delegation.delegationCid !== 'string' || !delegation.delegationCid ||
      typeof delegation.spaceId !== 'string' || !delegation.spaceId ||
      typeof delegation.verificationMethod !== 'string' || !delegation.verificationMethod ||
      !jwk || typeof jwk !== 'object' || Array.isArray(jwk) ||
      jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string' ||
      Object.keys(jwk).some((field) => !PUBLIC_JWK_FIELDS[field]) ||
      (delegation.primary !== undefined && typeof delegation.primary !== 'boolean') ||
      (delegation.spacePending !== undefined && delegation.spacePending !== true) ||
      serialized.length > 128 * 1024
    ) {
      return c.json({ error: 'Invalid public delegation' }, 400);
    }

    const expiresAt = new Date(now().getTime() + CODE_TTL_MS);
    await input.store.deleteExpired(now());
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const characters = randomBytes(8);
      const code = `${Array.from(characters.subarray(0, 4), (byte) => CODE_ALPHABET[byte & 31]).join('')}-${Array.from(characters.subarray(4), (byte) => CODE_ALPHABET[byte & 31]).join('')}`;
      if (await input.store.create(code, delegation, expiresAt)) {
        c.header('Cache-Control', 'no-store');
        return c.json({ code: code.toUpperCase(), expiresAt: expiresAt.toISOString() }, 201);
      }
    }
    return c.json({ error: 'Could not allocate delegation code' }, 503);
  });

  router.get('/:code', async (c) => {
    c.header('Cache-Control', 'no-store');
    const client = c.req.header('cf-connecting-ip') ?? c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
    const retryAfter = takeLookupSlot(client);
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

export function createPrismaDelegationCodeStore(): DelegationCodeStore {
  const prisma = createPrismaClient();
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
