import { randomBytes } from 'node:crypto';
import { Hono, type MiddlewareHandler } from 'hono';
import { createPrismaClient } from '@openkey/db';

const CODE_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const CODE_TTL_MS = 10 * 60 * 1000;
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
  get(code: string): Promise<{ delegation: unknown; expiresAt: Date } | null>;
  deleteExpired(before: Date): Promise<void>;
}

export function createDelegationCodeRouter(input: {
  store: DelegationCodeStore;
  now?: () => Date;
  sessionMiddleware: MiddlewareHandler;
}) {
  const router = new Hono();
  const now = input.now ?? (() => new Date());

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
        return c.json({ code, expiresAt: expiresAt.toISOString() }, 201);
      }
    }
    return c.json({ error: 'Could not allocate delegation code' }, 503);
  });

  router.get('/:code', async (c) => {
    c.header('Cache-Control', 'no-store');
    const code = c.req.param('code').toLowerCase();
    if (!/^[a-z2-7]{4}-[a-z2-7]{4}$/.test(code)) {
      return c.json({ error: 'Not found' }, 404);
    }
    const record = await input.store.get(code);
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
    async get(code) {
      return prisma.delegationCode.findUnique({ where: { code }, select: { delegation: true, expiresAt: true } });
    },
    async deleteExpired(before) {
      await prisma.delegationCode.deleteMany({ where: { expiresAt: { lte: before } } });
    },
  };
}
