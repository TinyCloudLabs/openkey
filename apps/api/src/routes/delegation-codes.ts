import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { Hono, type MiddlewareHandler } from 'hono';
import { createPrismaClient, Prisma, type PrismaClient } from '@openkey/db';
import {
  PUBLIC_DELEGATION_FIELDS as PUBLIC_DELEGATION_FIELD_LIST,
  PUBLIC_JWK_FIELDS as PUBLIC_JWK_FIELD_LIST,
} from '@openkey/delegation-code-fields';
import { requireAccountOriginForBearer } from '../middleware/bearer-origin';

// Codes are stored and looked up in lower case, the form every CLI since the
// broker shipped lower-cases to before its GET, so codes issued before codes
// were shown in upper case still redeem. Responses carry the upper-case form.
const CODE_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
// Five minutes, the same as the CLI's sign-in wait.
const CODE_TTL_MS = 5 * 60 * 1000;
// A client that redeems with a claim may fetch again, and acknowledge, for this long after redeeming.
const CLAIM_RETENTION_MS = 5 * 60 * 1000;
// A client-chosen secret of at least 128 bits, base64url. It binds a redeemed code to the redeemer.
const CLAIM_HEADER = 'OpenKey-Delegation-Claim';
const CLAIM_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;

export const PUBLIC_DELEGATION_FIELDS: Record<string, true> = Object.fromEntries(
  PUBLIC_DELEGATION_FIELD_LIST.map((field) => [field, true]),
) as Record<string, true>;
export const PUBLIC_JWK_FIELDS: Record<string, true> = Object.fromEntries(
  PUBLIC_JWK_FIELD_LIST.map((field) => [field, true]),
) as Record<string, true>;

export interface DelegationCodeStore {
  create(code: string, delegation: unknown, expiresAt: Date): Promise<boolean>;
  // Removes the code and returns it. Must be atomic: at most one caller gets a record for a given code.
  consume(code: string): Promise<{ delegation: unknown; expiresAt: Date } | null>;
  // Redeems for the holder of `claimHash`: the first call takes the code (atomic, one winner); the same
  // claim gets the delegation again until it is acknowledged or its retention ends. Anyone else gets null.
  claim(code: string, claimHash: string, now: Date): Promise<{ delegation: unknown } | null>;
  // Clears the delegation for the claim holder. Repeating it succeeds; any other claim gets false.
  acknowledge(code: string, claimHash: string, now: Date): Promise<boolean>;
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
  sessionMiddleware: MiddlewareHandler;
}) {
  const router = new Hono();
  const now = input.now ?? (() => new Date());
  const takeLookupSlot = createGlobalLookupLimiter(now);
  const takeAckSlot = createGlobalLookupLimiter(now);

  // undefined: no claim header (the original redeem-once behaviour); null: header present but malformed.
  const readClaimHash = (header: string | undefined): string | null | undefined => {
    if (header === undefined) return undefined;
    return CLAIM_PATTERN.test(header) ? createHash('sha256').update(header).digest('base64url') : null;
  };

  router.post('/', requireAccountOriginForBearer, input.sessionMiddleware, async (c) => {
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
    const retryAfter = takeLookupSlot();
    if (retryAfter > 0) {
      c.header('Retry-After', String(retryAfter));
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }
    const code = c.req.param('code').toLowerCase();
    if (!/^[a-z2-7]{4}-[a-z2-7]{4}$/.test(code)) {
      return c.json({ error: 'Not found' }, 404);
    }
    const claimHash = readClaimHash(c.req.header(CLAIM_HEADER));
    if (claimHash === null) return c.json({ error: 'Invalid claim' }, 400);
    if (claimHash !== undefined) {
      // The claim holder keeps the delegation until it acknowledges, so a lost response can be fetched again.
      // Anyone else, an expired code and an unknown code all get the same 404.
      const claimed = await input.store.claim(code, claimHash, now());
      if (!claimed) return c.json({ error: 'Not found' }, 404);
      return c.json({ delegation: claimed.delegation });
    }
    // Without a claim, redeeming removes the code: a second redeem, an expired code and an unknown code all get the same 404.
    const record = await input.store.consume(code);
    if (!record || record.expiresAt <= now()) {
      return c.json({ error: 'Not found' }, 404);
    }
    return c.json({ delegation: record.delegation });
  });

  router.post('/:code/ack', async (c) => {
    c.header('Cache-Control', 'no-store');
    const retryAfter = takeAckSlot();
    if (retryAfter > 0) {
      c.header('Retry-After', String(retryAfter));
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }
    const claimHash = readClaimHash(c.req.header(CLAIM_HEADER));
    if (!claimHash) return c.json({ error: 'Invalid claim' }, 400);
    const code = c.req.param('code').toLowerCase();
    // A wrong claim, an unclaimed code and an unknown code all get the same 404.
    if (!/^[a-z2-7]{4}-[a-z2-7]{4}$/.test(code) || !await input.store.acknowledge(code, claimHash, now())) {
      return c.json({ error: 'Not found' }, 404);
    }
    return c.json({ status: 'acknowledged' });
  });

  return router;
}

// Claim hashes are compared in constant time, in the application and not in a SQL equality.
function sameClaim(stored: string, given: string): boolean {
  const left = Buffer.from(stored);
  const right = Buffer.from(given);
  return left.length === right.length && timingSafeEqual(left, right);
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
    async claim(code, claimHash, now) {
      return prisma.$transaction(async (tx) => {
        const held = await tx.delegationCodeClaim.findUnique({ where: { code } });
        if (held?.delegation && !held.acknowledgedAt && held.redeemedAt.getTime() > now.getTime() - CLAIM_RETENTION_MS && sameClaim(held.claimHash, claimHash)) {
          return { delegation: held.delegation };
        }
        const row = await tx.delegationCode.findFirst({ where: { code, expiresAt: { gt: now } } });
        if (!row) return null;
        // Of concurrent redeems only the one that deletes the row takes the code.
        if ((await tx.delegationCode.deleteMany({ where: { code } })).count !== 1) return null;
        const claim = { claimHash, delegation: row.delegation as object, redeemedAt: now, acknowledgedAt: null };
        await tx.delegationCodeClaim.upsert({ where: { code }, create: { code, ...claim }, update: claim });
        return { delegation: row.delegation };
      });
    },
    async acknowledge(code, claimHash, now) {
      const held = await prisma.delegationCodeClaim.findUnique({ where: { code } });
      if (!held || !sameClaim(held.claimHash, claimHash)) return false;
      // Idempotent: a repeat finds nothing left to clear and still succeeds for the same claim.
      await prisma.delegationCodeClaim.updateMany({
        where: { code, claimHash: held.claimHash, acknowledgedAt: null },
        data: { acknowledgedAt: now, delegation: Prisma.DbNull },
      });
      return true;
    },
    async deleteExpired(before) {
      await prisma.delegationCode.deleteMany({ where: { expiresAt: { lte: before } } });
      await prisma.delegationCodeClaim.deleteMany({ where: { redeemedAt: { lte: new Date(before.getTime() - CLAIM_RETENTION_MS) } } });
    },
  };
}
