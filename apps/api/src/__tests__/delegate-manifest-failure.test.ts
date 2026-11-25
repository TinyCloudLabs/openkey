import { expect, spyOn, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import type { delegateRouter } from '../routes/delegate';

const user = { id: 'manifest-test-user' };
const address = '0x1111111111111111111111111111111111111111';
const key = { id: 'manifest-test-key', userId: user.id, address, keyType: 'MANAGED', archivedAt: null, sealedBlob: 'fixture' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const detail = 'fetch returned status 503';
replaceModules({
  '../middleware/session': () => ({ requireSession: createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('session', { id: 'manifest-test-session', userId: user.id });
    await next();
  }) }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({ ethereumKey: { findFirst: async () => key, findMany: async () => [key] } }) }),
  '../services/manifest-origin-fetch': () => ({ fetchAndBindWellKnownManifest: async () => ({ ok: false, reason: detail }) }),
});
// A file-specific router instance captures only this file's tests' mocks.
const { delegateRouter: router } = await import('../routes/delegate?manifest-failure-redaction' as string) as { delegateRouter: typeof delegateRouter };

test('the manifest failure detail stays in the server log', async () => {
  const spaceId = `tinycloud:pkh:eip155:1:${address}:default`;
  const siwe = prepareSession({
    address, chainId: 1, domain: 'openkey.so', jwk, spaceId, issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
    abilities: { kv: { [spaceId]: ['tinycloud.kv/get'] } },
  }).siwe;
  const stdout = spyOn(process.stdout, 'write').mockReturnValue(true);
  try {
    const response = await router.request('/authorize-sign-prepare', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: key.id, siwe, jwk, requestOrigin: 'https://openkey.so', reportedOrigin: 'https://manifest.test?query=private-fixture',
        presentation: { protocolVersion: 1, manifestDigest: 'a'.repeat(64) },
      }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ metadataTrust: { status: 'unsigned', reason: 'OpenKey could not verify the app manifest.' } });
    const lines = stdout.mock.calls.map(([line]) => String(line));
    expect(lines.some((line) => line.includes('delegate_origin_bind_failed') && line.includes(detail))).toBe(true);
    expect(lines.join('')).not.toContain('private-fixture');
  } finally {
    stdout.mockRestore();
  }
});
