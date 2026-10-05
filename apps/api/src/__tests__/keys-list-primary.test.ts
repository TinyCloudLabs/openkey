// TC-703: GET /api/keys marks the user's primary key (the active managed key
// flagged as the canonical TinyCloud key) with `isPrimary`.

import { beforeAll, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import type { keysRouter } from '../routes/keys';

const user = { id: 'user_1', email: 'alice@example.test' };
const createdAt = new Date('2026-01-01T00:00:00.000Z');
const record = (
  id: string,
  keyIndex: number,
  keyType: 'MANAGED' | 'EXTERNAL',
  isCanonicalTinyCloud: boolean,
  archivedAt: Date | null = null,
) => ({
  id, userId: user.id, address: `0x${String(keyIndex + 1).repeat(40)}`, publicKey: '0x', keyType, keyIndex,
  label: null, isCanonicalTinyCloud, archivedAt, createdAt, sealedBlob: keyType === 'MANAGED' ? 'sealed' : null,
});
const records = [
  record('key_primary', 0, 'MANAGED', true),
  record('key_managed', 1, 'MANAGED', false),
  record('key_external', 2, 'EXTERNAL', false),
  // The canonical flag survives archiving, but an archived key is never primary.
  record('key_archived', 3, 'MANAGED', true, new Date('2026-02-01T00:00:00.000Z')),
];

const findMany = mock(async ({ where, select }: { where: { userId: string; archivedAt?: null }; select: Record<string, boolean> }) =>
  records
    .filter((key) => key.userId === where.userId && (!('archivedAt' in where) || key.archivedAt === null))
    .map((key) => Object.fromEntries(Object.keys(select).map((field) => [field, key[field as keyof typeof key]]))));

mock.module('@openkey/db', () => ({ createPrismaClient: () => ({ ethereumKey: { findMany } }) }));
mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), isInTee: () => false }),
  seal: mock(async () => 'sealed'),
  unseal: mock(async () => '0x'),
  generatePrivateKey: () => '0x',
  getAddressFromPrivateKey: () => '0x',
}));
mock.module('../services/tinycloud-bootstrap', () => ({ ensureTinyCloudBootstrapForApprovedSign: mock(async () => ({ status: 'skipped' })) }));
mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
    await next();
  }),
}));

let router: typeof keysRouter;

beforeAll(async () => {
  ({ keysRouter: router } = await import('../routes/keys?keys-list-primary-isolated' as string));
});

async function listKeys(query = '') {
  const res = await router.request(`/${query}`);
  expect(res.status).toBe(200);
  return ((await res.json()) as { keys: Array<Record<string, unknown>> }).keys;
}

describe('GET /api/keys isPrimary (TC-703)', () => {
  test('marks only the active canonical managed key as primary', async () => {
    const keys = await listKeys();
    expect(keys.map((key) => [key.id, key.isPrimary])).toEqual([
      ['key_primary', true],
      ['key_managed', false],
      ['key_external', false],
    ]);
  });

  test('an archived key is never primary, even when flagged canonical', async () => {
    const keys = await listKeys('?archived=true');
    expect(keys.find((key) => key.id === 'key_archived')?.isPrimary).toBe(false);
    expect(keys.filter((key) => key.isPrimary === true).map((key) => key.id)).toEqual(['key_primary']);
  });

  test('reports isPrimary instead of the internal canonical flag', async () => {
    const [key] = await listKeys();
    expect(key).not.toHaveProperty('isCanonicalTinyCloud');
    expect(key).not.toHaveProperty('sealedBlob');
    expect(Object.keys(key!).sort()).toEqual(
      ['address', 'archivedAt', 'createdAt', 'id', 'isPrimary', 'keyIndex', 'keyType', 'label', 'publicKey'],
    );
  });
});
