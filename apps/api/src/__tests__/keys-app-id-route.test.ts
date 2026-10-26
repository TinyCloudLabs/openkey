import { afterAll, beforeAll, beforeEach, expect, mock, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { rmSync, writeFileSync } from 'node:fs';

const testHome = execFileSync('mktemp', ['-d', '-p', '/var/tmp', 'keysid.XXXXXX'], { encoding: 'utf8' }).trim();
const homeNames = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'TC_HOME', 'TINYCLOUD_HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME'] as const;
const savedHomes = homeNames.map(name => [name, process.env[name]] as const);
for (const name of homeNames) process.env[name] = testHome;
if (!testHome.startsWith('/var/tmp/keysid.') || homeNames.some(name => process.env[name] !== testHome)) {
  throw new Error('The keys-app-id route test home is not isolated');
}
writeFileSync(`${testHome}/path-record`, `${testHome}\n`, { mode: 0o600 });
afterAll(() => {
  for (const [name, value] of savedHomes) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(testHome, { recursive: true, force: true });
});

const { createMiddleware } = await import('hono/factory');
const { privateKeyToAccount } = await import('viem/accounts');
const { prepareSession } = await import('@tinycloud/node-sdk-wasm');
const { mockModules, replaceModules } = await import('./mock-module');
const { bindWellKnownManifestBytes, canonicalManifestSha256Hex } = await import('../services/manifest-origin-fetch');

const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const address = account.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const origin = 'https://tinycloud.chat';
const keysId = 'chat.tinycloud.tinychat';
const dataId = 'dev.pages.okqa-dev';
const owner = `did:pkh:eip155:1:${address}`;
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const resource = `urn:tinycloud:encryption:${owner}:default/apps/${keysId}/token`;
const keyRecord = {
  id: 'key_1', userId: user.id, address, keyType: 'MANAGED', archivedAt: null,
  sealedBlob: 'sealed-blob', sealingContext: null,
};

let manifest: Record<string, unknown> = {};
const fetchAndBindWellKnownManifest = mock(async () => bindWellKnownManifestBytes(
  new TextEncoder().encode(JSON.stringify(manifest)), canonicalManifestSha256Hex(manifest),
));

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({
    ethereumKey: {
      findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => where.userId === user.id ? keyRecord : null),
      findMany: mock(async () => [keyRecord]),
      findUnique: mock(async () => keyRecord),
    },
    user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
    tinyCloudBootstrapState: {},
  }) }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
    createWalletFromPrivateKey: () => account,
    generatePrivateKey: () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    getAddressFromPrivateKey: () => address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }),
  '../services/manifest-origin-fetch': () => ({ fetchAndBindWellKnownManifest }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];
beforeAll(async () => {
  ({ delegateRouter: router } = await import('../routes/delegate?keys-app-id-route' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import('../services/authorization-signing?keys-app-id-route' as string));
});
beforeEach(() => {
  manifest = { app_id: dataId, keys_app_id: keysId, keys: [{ path: `apps/${keysId}/token`, abilities: ['decrypt'] }] };
  resetContexts?.();
});

async function prepare() {
  const now = new Date();
  const siwe = prepareSession({
    address, chainId: 1, domain: 'tinycloud.chat', issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(), spaceId: space, jwk,
    abilities: { kv: { [space]: ['tinycloud.kv/get', 'tinycloud.kv/put'] } } as never,
    rawAbilities: { [resource]: ['tinycloud.encryption/decrypt'] },
  }).siwe;
  const response = await router.request('/authorize-sign-prepare', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      keyId: keyRecord.id, siwe, jwk, host: 'https://node.tinycloud.xyz',
      requestOrigin: origin, reportedOrigin: origin,
      presentation: { manifestDigest: canonicalManifestSha256Hex(manifest), displayName: 'TinyChat' },
    }),
  });
  return { status: response.status, body: await response.json() as { authorizationContextToken?: string; metadataTrust?: { status: string }; code?: string; error?: string } };
}

test('the API admits a separate host-bound key namespace from the fetched manifest', async () => {
  const { status, body } = await prepare();
  expect(status).toBe(200);
  expect(body.metadataTrust?.status).toBe('origin-bound');
});

test('the API refuses a key namespace that belongs to another origin', async () => {
  manifest = { app_id: keysId, keys_app_id: 'xyz.tinycloud.tinychat', keys: [{ path: 'apps/xyz.tinycloud.tinychat/token', abilities: ['decrypt'] }] };
  const { status, body } = await prepare();
  expect(status).toBe(403);
  expect(body).toMatchObject({ code: 'app_key_grant_refused', error: "This app doesn't belong to this website, so OpenKey didn't approve its keys." });
  expect(body.authorizationContextToken).toBeUndefined();
});
