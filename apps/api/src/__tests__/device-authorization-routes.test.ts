import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, test } from 'bun:test';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import { mockModules, replaceModules } from './mock-module';

replaceModules({
  '../middleware/session': () => ({ requireSession: createMiddleware(async (c) => c.json({ error: 'session required' }, 401)) }),
});
await mockModules({ '@openkey/db': () => ({ createPrismaClient: () => ({}) }) });
// The router creates a Prisma-backed singleton at module load; import after
// installing the test's database substitute to keep this file isolated.
const { createDeviceAuthorizationRouter } = await import('../routes/device-authorization?device-authorization-routes' as string);

const ownerDid = 'did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const secret = 'device-secret-with-at-least-256-bits-of-entropy';
const verifier = 'pkce-verifier-with-at-least-256-bits-of-entropy';

function appForRequest() {
  const store = new MemoryDeviceAuthorizationStore((userId, owner) => userId === 'owner-user' && owner === ownerDid);
  const service = new DeviceAuthorizationService(store, {
    verificationOrigin: 'https://openkey.so',
    encryptionSecret: 'test-device-authorization-secret-is-long-enough',
  });
  const sessionMiddleware = createMiddleware(async (c, next) => {
    const userId = c.req.header('x-test-user');
    if (!userId) return c.json({ error: 'session required' }, 401);
    c.set('user', { id: userId });
    await next();
  });
  const app = new Hono();
  app.route('/api/device-authorizations', createDeviceAuthorizationRouter({ service, sessionMiddleware: sessionMiddleware as never }));
  const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
  const request = {
    owner: ownerDid,
    deviceSecretHash: createHash('sha256').update(secret).digest('base64url'),
    codeChallenge: createHash('sha256').update(verifier).digest('base64url'),
    sessionDid: sessionDidForPublicJwk(publicJwk),
    publicJwk,
    relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }),
    permissions: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }],
    nodeOrigin: 'https://node.tinycloud.xyz',
    shareOrigin: 'https://share.tinycloud.xyz',
  };
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) => app.request(`/api/device-authorizations${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
  });
  return { app, request, post };
}

test('public lookup cannot redeem a denied owner-bound request or reveal private credentials', async () => {
  const { app, request, post } = appForRequest();
  const started = await post('', request);
  expect(started.status).toBe(201);
  const { transactionId, userCode } = await started.json();
  const lookup = await app.request(`/api/device-authorizations/lookup?user_code=${encodeURIComponent(userCode)}`);
  expect(lookup.status).toBe(200);
  const visible = await lookup.json();
  expect(visible).toMatchObject({ id: transactionId, ownerDid, sessionDid: request.sessionDid });
  for (const field of ['deviceSecretHash', 'codeChallenge', 'requestIpHash', 'encryptedResult']) {
    expect(visible).not.toHaveProperty(field);
  }
  expect(JSON.stringify(visible)).not.toContain(request.deviceSecretHash);

  const denialPath = `/${transactionId}/deny`;
  const unauthenticated = await post(denialPath, {});
  expect(unauthenticated.status).toBe(401);
  const stranger = await post(denialPath, {}, { 'x-test-user': 'stranger' });
  const nonexistent = await post('/unrecognized/deny', {}, { 'x-test-user': 'stranger' });
  expect(stranger.status).toBe(404);
  expect(await stranger.json()).toEqual(await nonexistent.json());
  const owner = await post(denialPath, {}, { 'x-test-user': 'owner-user' });
  expect(owner.status).toBe(200);
  expect(await owner.json()).toEqual({ denied: true });
  const hidden = await app.request(`/api/device-authorizations/lookup?user_code=${encodeURIComponent(userCode)}`);
  expect(hidden.status).toBe(404);
  const credentials = { transactionId, deviceSecret: secret, codeVerifier: verifier };
  expect((await post('/token', { ...credentials, deviceSecret: 'wrong' })).status).toBe(401);
  const denied = await post('/token', credentials);
  expect(denied.status).toBe(403);
  expect(await denied.json()).toEqual({ error: 'access_denied', errorDescription: 'device authorization denied' });
});
