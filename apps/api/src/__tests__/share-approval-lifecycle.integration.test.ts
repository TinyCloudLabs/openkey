import { test, expect, beforeAll, afterAll } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { readdir, readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { serializeSignedCookie } from 'better-call';
import { shareWindowContexts as windows } from '../services/share-window-session';
import { strictSessionDid } from '../services/device-authorization';
import type { PrismaClient } from '@openkey/db';
import type { Hono } from 'hono';
import type { SessionContext } from '../middleware/session';
import type { auth as Auth } from '../auth';
import { z } from 'zod';
if (process.env.OPENKEY_SHARE_LIFECYCLE_CHILD !== '1') {
  test('real auth lifecycle retires pending share approvals', async () => {
    const scratch = await mkdtemp(join(tmpdir(), 'tc2927-auth-lifecycle-'));
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: new URL('../../../../', import.meta.url).pathname,
        env: { ...process.env, OPENKEY_SHARE_LIFECYCLE_CHILD: '1', OPENKEY_SHARE_LIFECYCLE_DIR: scratch,
          NODE_ENV: 'test', TEE_MODE: 'development', BETTER_AUTH_URL: 'https://api.openkey.test',
          BETTER_AUTH_SECRET: 'tc2927-synthetic-local-test-secret-only', WEBAUTHN_RP_ID: 'openkey.test',
          WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
          RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '' },
        stdout: 'pipe', stderr: 'pipe',
      });
      const [out, err, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(status, out + err).toBe(0);
    } finally { await rm(scratch, { recursive: true, force: true }); }
  }, 90000);
} else {
const previewSchema = z.object({ requestId: z.string(), intentDigest: z.string(), shareId: z.string(),
  prepared: z.object({ siwe: z.string() }),
  assertion: z.object({ token: z.string(), options: z.object({ challenge: z.string() }) }) });
const issuedSchema = z.object({ windowContextToken: z.string() });
const root = new URL('../../../../', import.meta.url).pathname;
let auth: typeof Auth, db: PrismaClient, router: Hono<SessionContext>;
const wallet = Wallet.createRandom();
const account = { userId: 'owner', authSessionId: 'session-A', authSessionGeneration: 'fixture-generation', keyId: 'key', address: wallet.address, keyType: 'EXTERNAL' as const };
let cookie: string;
const rp = 'openkey.test', origin = 'https://openkey.test';
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = publicKey.export({ format: 'jwk' });
const cose = Buffer.concat([Buffer.from('a5010203262001215820', 'hex'), Buffer.from(jwk.x!, 'base64url'), Buffer.from('225820', 'hex'), Buffer.from(jwk.y!, 'base64url')]);
const credentialID = Buffer.from('review-credential').toString('base64url');
let counter = 0;
beforeAll(async () => {
  const dir = join(process.env.OPENKEY_SHARE_LIFECYCLE_DIR!, 'db');
  const pglite = new PGlite(dir);
  for (const name of (await readdir(`${root}packages/db/prisma/migrations`, { withFileTypes: true })).filter(x => x.isDirectory()).map(x => x.name).sort()) {
    await pglite.exec(await readFile(`${root}packages/db/prisma/migrations/${name}/migration.sql`, 'utf8'));
  }
  await pglite.close();
  process.env.DATABASE_URL = `pglite:${dir}`;
  // Load only after setting the private database URL; both runtime modules create clients at module initialization.
  ({ auth, prisma: db } = await import('../auth'));
  for (const id of ['owner', 'other']) await db.user.create({ data: { id, email: `${id}@example.test`, emailVerified: true } });
  await db.session.create({ data: { id: account.authSessionId, userId: account.userId, token: 'synthetic-A', expiresAt: new Date(Date.now() + 7 * 86400_000) } });
  await db.session.create({ data: { id: 'session-B', userId: account.userId, token: 'synthetic-B', expiresAt: new Date(Date.now() + 7 * 86400_000) } });
  await db.ethereumKey.create({ data: { id: 'key', userId: 'owner', address: wallet.address, publicKey: wallet.address, keyType: 'EXTERNAL' } });
  await db.passkey.create({ data: { id: 'credential', userId: 'owner', credentialID, publicKey: cose.toString('base64'), counter: 0, countsForStepUp: true, deviceType: 'singleDevice', backedUp: false } });
  const context = await auth.$context;
  cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, 'synthetic-A', context.secret)).split(';')[0]!;
  router = (await import('../routes/share-approval-runtime')).shareApprovalRouter;
}, 90000);
afterAll(async () => { await db?.$disconnect(); });
const call = (phase: string, body: unknown, useCookie = cookie) => router.request(`http://api.test/${phase}`, { method: 'POST', headers: { origin, cookie: useCookie, 'content-type': 'application/json' }, body: JSON.stringify(body) });
async function intent() {
  const publicJwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const siwe = new SiweMessage({ domain: 'thirdparty.example', address: wallet.address, uri: strictSessionDid(publicJwk), version: '1', chainId: 1, nonce: '12345678', issuedAt: new Date().toISOString(), expirationTime: new Date(Date.now() + 3600_000).toISOString() }).prepareMessage();
  return { keyId: 'key', origin: 'https://thirdparty.example', session: { siwe, signature: await wallet.signMessage(siwe), publicJwk }, expiresAt: new Date(Date.now() + 1800_000).toISOString() };
}
async function prepare() {
  const outer = crypto.randomUUID();
  const w = await call('window', { keyId: 'key', requestId: outer, observedOrigin: 'https://thirdparty.example' });
  expect(w.status).toBe(200);
  const issued = issuedSchema.parse(await w.json());
  const requestIntent = await intent();
  const options = await call('options', { requestId: outer, windowContextToken: issued.windowContextToken, intent: requestIntent });
  expect(options.status).toBe(200);
  return { preview: previewSchema.parse(await options.json()), issued, outer, requestIntent };
}
async function verified() {
  const f = await prepare();
  const p = f.preview;
  const body = { requestId: p.requestId, keyId: 'key', token: p.assertion.token };
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: p.assertion.options.challenge, origin }));
  const count = Buffer.alloc(4); count.writeUInt32BE(++counter);
  const data = Buffer.concat([createHash('sha256').update(rp).digest(), Buffer.from([5]), count]);
  const response = { id: credentialID, rawId: credentialID, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: client.toString('base64url'), authenticatorData: data.toString('base64url'), signature: sign('sha256', Buffer.concat([data, createHash('sha256').update(client).digest()]), privateKey).toString('base64url') } };
  expect((await call('verify', { ...body, response })).status).toBe(200);
  expect((await call('resume', body)).status).toBe(200);
  return { ...f, body };
}
test('a different auth session cannot claim, advance or cancel an approval', async () => {
  const context = await auth.$context;
  const b = (await serializeSignedCookie(context.authCookies.sessionToken.name, 'synthetic-B', context.secret)).split(';')[0]!;
  const outer = crypto.randomUUID();
  const w = issuedSchema.parse(await (await call('window', { keyId: 'key', requestId: outer, observedOrigin: 'https://thirdparty.example' })).json());
  for (const phase of ['options', 'window/cancel']) {
    const body = phase === 'options' ? { requestId: outer, windowContextToken: w.windowContextToken, intent: await intent() } : { requestId: outer, keyId: 'key', windowContextToken: w.windowContextToken };
    expect((await call(phase, body, b)).status).toBe(403);
  }
  const f = await verified();
  for (const phase of ['verify', 'resume', 'preview', 'sign', 'cancel']) {
    const extra = phase === 'verify' ? { response: {} } : phase === 'sign' ? { intentDigest: f.preview.intentDigest, externalSignature: await wallet.signMessage(f.preview.prepared.siwe) } : {};
    expect((await call(phase, { ...f.body, ...extra }, b)).status).toBe(403);
  }
  expect((await call('preview', f.body)).status).toBe(200);
});
test('real session refresh refuses resumed share approvals', async () => {
  const f = await verified();
  const before = await db.session.findUnique({ where: { id: 'session-A' } });
  await db.session.update({ where: { id: 'session-A' }, data: { createdAt: new Date(Date.now() - 2 * 86400_000), expiresAt: new Date(Date.now() + 5 * 86400_000) } });
  const response = await auth.handler(new Request('https://api.openkey.test/api/auth/get-session', { headers: { cookie } }));
  expect(response.status).toBe(200);
  const after = await db.session.findUnique({ where: { id: 'session-A' } });
  if (!before || !after) throw new Error('fixture session disappeared');
  expect(after.updatedAt.getTime()).toBeGreaterThan(before.updatedAt.getTime());
  const result = await call('sign', { ...f.body, intentDigest: f.preview.intentDigest, externalSignature: await wallet.signMessage(f.preview.prepared.siwe) });
  expect(result.status).toBe(403);
});
test('a direct Prisma session update bypassing auth hooks refuses a previously resumed approval', async () => {
  const f = await verified();
  await db.session.update({ where: { id: 'session-A' }, data: { lastEmailOtpAt: new Date() } });
  expect((await call('sign', { ...f.body, intentDigest: f.preview.intentDigest,
    externalSignature: await wallet.signMessage(f.preview.prepared.siwe) })).status).toBe(403);
});
test('real passkey sign-in replacement retires the previous browser approval', async () => {
  const f = await verified();
  const optionsResponse = await auth.handler(new Request('https://api.openkey.test/api/auth/passkey/generate-authenticate-options', {
    headers: { origin, cookie },
  }));
  expect(optionsResponse.status).toBe(200);
  const options = z.object({ challenge: z.string() }).parse(await optionsResponse.json());
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin }));
  const count = Buffer.alloc(4); count.writeUInt32BE(++counter);
  const data = Buffer.concat([createHash('sha256').update(rp).digest(), Buffer.from([5]), count]);
  const response = { id: credentialID, rawId: credentialID, type: 'public-key', clientExtensionResults: {}, response: {
    clientDataJSON: client.toString('base64url'), authenticatorData: data.toString('base64url'),
    signature: sign('sha256', Buffer.concat([data, createHash('sha256').update(client).digest()]), privateKey).toString('base64url'),
  } };
  const loginCookie = [cookie, ...optionsResponse.headers.getSetCookie().map(value => value.split(';')[0])].join('; ');
  const result = await auth.handler(new Request('https://api.openkey.test/api/auth/passkey/verify-authentication', {
    method: 'POST', headers: { origin, cookie: loginCookie, 'content-type': 'application/json' }, body: JSON.stringify({ response }),
  }));
  expect(result.status).toBe(200);
  expect((await call('sign', { ...f.body, intentDigest: f.preview.intentDigest,
    externalSignature: await wallet.signMessage(f.preview.prepared.siwe) })).status).toBe(403);
});
test('real OTP account replacement invalidates the previous browser session share state', async () => {
  const f = await verified();
  const outer = crypto.randomUUID();
  const issued = windows.issue(account, outer, 'https://thirdparty.example');
  const otpApi = auth.api as typeof auth.api & { createVerificationOTP(input: { body: { email: string; type: 'sign-in' } }): Promise<string> };
  const otp = await otpApi.createVerificationOTP({ body: { email: 'other@example.test', type: 'sign-in' } });
  const response = await auth.handler(new Request('https://api.openkey.test/api/auth/sign-in/email-otp', { method: 'POST', headers: { origin, cookie, 'content-type': 'application/json' }, body: JSON.stringify({ email: 'other@example.test', otp }) }));
  expect(response.status).toBe(200);
  expect(z.object({ user: z.object({ id: z.string() }) }).parse(await response.json()).user.id).toBe('other');
  expect(() => windows.read(issued.token, account, outer)).toThrow();
  expect(await db.session.count({ where: { id: 'session-A' } })).toBe(1);
  expect((await call('sign', { ...f.body, intentDigest: f.preview.intentDigest, externalSignature: await wallet.signMessage(f.preview.prepared.siwe) })).status).toBe(403);

});
test('real sign-out delete hook terminally invalidates the session window', async () => {
  const outer = crypto.randomUUID();
  const issued = windows.issue(account, outer, 'https://thirdparty.example');
  const response = await auth.handler(new Request('https://api.openkey.test/api/auth/sign-out', { method: 'POST', headers: { origin, cookie } }));
  expect(response.status).toBe(200);
  expect(await db.session.count({ where: { id: 'session-A' } })).toBe(0);
  expect(() => windows.read(issued.token, account, outer)).toThrow();
});

}
