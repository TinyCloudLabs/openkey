import { afterAll, beforeEach, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { mockModules, replaceModules } from './mock-module';

const savedPause = process.env.OPENKEY_PAUSE_NEW_CUSTODY;
afterAll(() => {
  if (savedPause === undefined) delete process.env.OPENKEY_PAUSE_NEW_CUSTODY;
  else process.env.OPENKEY_PAUSE_NEW_CUSTODY = savedPause;
});
const deriveKey = mock(async () => new Uint8Array(32));
const seal = mock(async () => 'sealed');
const generatePrivateKey = mock(() => '0x01');
const generateNostrKeypair = mock(() => ({ secretKeyHex: '01', pubkeyHex: '02', npub: 'npub1test' }));
const insert = mock(async () => ({ id: 'new-key' }));
let existing: { id: string; npub: string } | null = null;
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({
    ethereumKey: { findFirst: async () => null, create: insert },
    nostrKey: { findFirst: async () => existing, upsert: insert },
  }) }),
  '@openkey/tee': () => ({ createTeeClient: () => ({ deriveKey }), seal,
    unseal: mock(), generatePrivateKey, getAddressFromPrivateKey: () => '0x02',
    generateNostrKeypair, computeEventId: mock(), signNostrEvent: mock(), SUPPORTED_NOSTR_KINDS: new Set([9, 22242]) }),
});
replaceModules({ '../middleware/session': () => ({ requireSession: createMiddleware(async (c, next) => {
  c.set('user', { id: 'custody-user', email: 'custody@example.test' });
  c.set('session', { id: 'custody-session', userId: 'custody-user', expiresAt: new Date(Date.now() + 60_000) });
  await next();
}) }) });
// File-specific module instances isolate process-wide test substitutes.
const { keysRouter } = await import('../routes/keys?custody-pause-routes' as string);
const { nostrKeysRouter } = await import('../routes/nostr-keys?custody-pause-routes' as string);
beforeEach(() => {
  process.env.OPENKEY_PAUSE_NEW_CUSTODY = 'true';
  existing = null;
  for (const operation of [deriveKey, seal, generatePrivateKey, generateNostrKeypair, insert]) operation.mockClear();
});
const request = { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' };
function noNewCustody() {
  expect(generatePrivateKey).not.toHaveBeenCalled();
  expect(generateNostrKeypair).not.toHaveBeenCalled();
  expect(deriveKey).not.toHaveBeenCalled();
  expect(seal).not.toHaveBeenCalled();
  expect(insert).not.toHaveBeenCalled();
}
test('managed generation refuses before generating, deriving, sealing or inserting', async () => {
  const response = await keysRouter.request('/generate', request);
  expect(response.status).toBe(503);
  expect(await response.json()).toMatchObject({ code: 'NEW_CUSTODY_PAUSED' });
  noNewCustody();
});
test('first Nostr identity refuses before generating, deriving, sealing or inserting', async () => {
  const response = await nostrKeysRouter.request('/', request);
  expect(response.status).toBe(503);
  expect(await response.json()).toMatchObject({ code: 'NEW_CUSTODY_PAUSED' });
  noNewCustody();
});
test('existing Nostr identity returns without new custody while paused', async () => {
  existing = { id: 'existing-nostr', npub: 'npub1existing' };
  const response = await nostrKeysRouter.request('/', request);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ key: existing });
  noNewCustody();
});
