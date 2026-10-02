import { afterAll, beforeAll, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
let signatures = 0;
const key = { id: 'key-1', userId: 'user-1', address: account.address, keyType: 'MANAGED', archivedAt: null, sealedBlob: 'sealed', sealingContext: null };
const manifest = { app_id: 'fitness', name: 'Fitness', space: 'applications', defaults: false, includePublicSpace: false, permissions: [{ service: 'tinycloud.sql', path: 'fitness', skipPrefix: true, actions: ['read', 'write'] }] };
mock.module('@openkey/db', () => ({ createPrismaClient: () => ({ ethereumKey: { findFirst: async ({ where }: any) => where.userId === key.userId && where.id === key.id ? key : null } }) }));
mock.module('@openkey/tee', () => ({ createTeeClient: () => ({ deriveKey: async () => new Uint8Array(32), getQuote: async () => 'quote', isInTee: () => false }), unseal: async () => privateKey, createWalletFromPrivateKey: () => ({ ...account, signMessage: async (input: any) => { signatures++; return account.signMessage(input); } }) }));
mock.module('../middleware/session', () => ({ requireSession: createMiddleware(async (c, next) => {
  if (!c.req.header('x-test-user')) return c.json({ error: 'Unauthorized' }, 401);
  c.set('user', { id: c.req.header('x-test-user') }); await next();
}) }));
let router: any;
const originalFetch = globalThis.fetch;
const network: string[] = [];
beforeAll(async () => {
  globalThis.fetch = (async (input: string, options: RequestInit) => {
    network.push(input);
    expect(options.method).toBe('POST');
    if (input.endsWith('/delegate')) return Response.json({ activated: ['account', 'applications'], skipped: [] });
    if (input.endsWith('/invoke')) {
      if ((options.headers as Record<string, string>)['x-tinycloud-limit']) return Response.json(['applications/fitness']);
      return Response.json({ app_id: 'fitness', manifests: [manifest] });
    }
    throw new Error('Unexpected network operation');
  }) as typeof fetch;
  router = (await import('../routes/delegate')).delegateRouter;
});
afterAll(() => { globalThis.fetch = originalFetch; });
const request = { discoveryProtocolVersion: 1, keyId: key.id, host: 'https://node.tinycloud.xyz', jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } };
const post = (path: string, body: any, user = 'user-1') => router.request(path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-test-user': user }, body: JSON.stringify(body) });
test('public capabilities identify the running discovery API protocol without owner access', async () => {
  const before = signatures;
  const response = await router.request('/app-read-capabilities');
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(await response.json()).toEqual({ schemaVersion: 1, protocolVersion: 1, implementationVersion: '1', discovery: 'app-read', scope: 'registry-and-selected-app', transport: 'paste' });
  expect(signatures).toBe(before);
});
test('real managed routes discover then approve one exact multi-space proof', async () => {
  const found = await post('/app-read-discovery', request);
  expect(found.status).toBe(200);
  const discovery = await found.json();
  const application = discovery.applications[0];
  const selection = { discoveryToken: discovery.discoveryToken, appId: application.appId, selectionDigest: application.selectionDigest };
  const preview = await post('/prepare', { ...request, ...selection });
  expect(preview.status).toBe(200);
  const prepared = await preview.json();
  expect(prepared.appReadSelection.appId).toBe('fitness');
  const approved = await post('/', { ...request, ...selection, prepared: prepared.prepared, authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys, protocolVersion: 1 });
  if (approved.status !== 200) throw new Error(JSON.stringify(await approved.json()));
  expect(approved.status).toBe(200);
  const proof = await approved.json();
  expect(proof.signedMessage).toBe(prepared.prepared.siwe);
  expect(proof.appReadSelection.selectionDigest).toBe(application.selectionDigest);
  expect(proof.appReadSelection.permissions).toEqual(application.permissions);
  const recap = parseRecapFromSiwe(proof.signedMessage);
  expect(recap).toHaveLength(4);
  expect(recap.every((p: any) => p.actions.every((a: string) => !/put|write|schema|host/.test(a)))).toBe(true);
  expect(network.every(url => url.endsWith('/delegate') || url.endsWith('/invoke'))).toBe(true);
});
test('selection drift and narrowed app scopes are rejected before a final signature', async () => {
  const discovery = await (await post('/app-read-discovery', request)).json();
  const application = discovery.applications[0];
  const selection = { discoveryToken: discovery.discoveryToken, appId: application.appId, selectionDigest: application.selectionDigest };
  const prepared = await (await post('/prepare', { ...request, ...selection })).json();
  const before = signatures;
  const narrowed = await post('/prepare', { ...request, ...selection, actionKeys: prepared.selectedActionKeys.filter((key: string) => !key.endsWith('tinycloud.sql/read')) });
  expect(narrowed.status).toBe(400);
  const approval = { ...request, ...selection, prepared: prepared.prepared, authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys, protocolVersion: 1 };
  for (const changed of [{ discoveryToken: undefined }, { appId: 'other' }, { selectionDigest: '0'.repeat(64) }, { prepared: { ...prepared.prepared, siwe: prepared.prepared.siwe.replace('tinycloud.sql/read', 'tinycloud.sql/write') + '\n' } }, { permissions: [{ service: 'tinycloud.sql', space: 'applications', path: 'fitness', actions: ['tinycloud.sql/write'] }] }]) {
    expect((await post('/', { ...approval, ...changed })).status).toBe(400);
  }
  expect(signatures).toBe(before);
  expect((await post('/', approval)).status).toBe(200);
  expect(signatures).toBe(before + 1);
});
test('discovery is session-authenticated and ownership-bound', async () => {
  expect((await post('/app-read-discovery', request, '')).status).toBe(401);
  expect((await post('/app-read-discovery', request, 'other')).status).toBe(400);
  expect((await post('/app-read-discovery', { ...request, host: 'https://attacker.example' })).status).toBe(400);
});
test('lost discovery and prepared contexts fail closed with a fresh-review remedy', async () => {
  const discovery = await (await post('/app-read-discovery', request)).json();
  const application = discovery.applications[0];
  const selection = { discoveryToken: discovery.discoveryToken, appId: application.appId, selectionDigest: application.selectionDigest };
  const missingDiscovery = await post('/prepare', { ...request, ...selection, discoveryToken: 'unknown-worker-token' });
  expect(missingDiscovery.status).toBe(400);
  expect(await missingDiscovery.json()).toMatchObject({ code: 'app_read_discovery_expired', error: expect.stringContaining('Choose your key and application again') });
  const prepared = await (await post('/prepare', { ...request, ...selection })).json();
  _resetAuthorizationContextStoreForTests();
  const before = signatures;
  const approved = await post('/', { ...request, ...selection, prepared: prepared.prepared, authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys, protocolVersion: 1 });
  expect(approved.status).toBe(400);
  expect(await approved.json()).toMatchObject({ code: 'app_read_prepared_context_expired', error: expect.stringContaining('Choose your key and application again') });
  expect(signatures).toBe(before);
});
