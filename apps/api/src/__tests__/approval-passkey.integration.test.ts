// TC-3442: the passkey-approval setting and the request-bound passkey check, against the real API on PGlite with
// the tracked migrations. Runs in a child process: the API reads its relying party and database when loaded.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
import { createSoftPasskey } from './soft-passkey';
import { approvalPasskeyOffer, approvalRequestDigest, checkApprovalPasskey, messageApprovalSensitivity } from '../services/approval-passkey';

const root = resolve(import.meta.dir, '../../../..');
const web = 'https://openkey.test';

describe('which messages are sensitive', () => {
  const signer = '0x1111111111111111111111111111111111111111';
  const space = `tinycloud:pkh:eip155:1:${signer}:default`;
  const hex = (text: string) => `0x${Buffer.from(text).toString('hex')}`;
  const siwe = (att?: Record<string, Record<string, unknown[]>>) => [
    'app.example wants you to sign in with your Ethereum account:', signer, '', 'Sign in', '',
    'URI: https://app.example', 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-07-31T00:00:00.000Z',
    ...(att ? ['Resources:', `- urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`] : []),
  ].join('\n');
  const appData = siwe({ [space]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}], 'tinycloud.capabilities/read': [{}] } });
  const secretRead = siwe({ [`${space}/vault/secrets/DEPLOY_KEY`]: { 'tinycloud.kv/get': [{}] } });

  test('a SIWE is as sensitive as its most sensitive grant, by the review screen classifier', () => {
    expect(messageApprovalSensitivity(siwe(), signer)).toBe('standard');
    expect(messageApprovalSensitivity(appData, signer)).toBe('standard');
    expect(messageApprovalSensitivity(secretRead, signer)).toBe('sensitive');
  });

  test('a message that cannot be classified is sensitive, and SIWE inside hex is read as SIWE', () => {
    expect(messageApprovalSensitivity('Please sign this receipt: order #4472', signer)).toBe('sensitive');
    expect(messageApprovalSensitivity('0xdeadbeef', signer)).toBe('sensitive');
    expect(messageApprovalSensitivity(hex(secretRead), signer)).toBe('sensitive');
    expect(messageApprovalSensitivity(hex(appData), signer)).toBe('standard');
  });
});

if (process.env.OPENKEY_APPROVAL_PASSKEY_TEST_CHILD !== '1') {
  test('the passkey-approval setting across the API', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_APPROVAL_PASSKEY_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'approval-passkey-isolated-test-secret',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: web,
        CORS_ORIGIN: web,
        RESEND_API_KEY: '',
        GOOGLE_CLIENT_ID: '',
        GOOGLE_CLIENT_SECRET: '',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(exitCode, stdout + stderr).toBe(0);
  }, 300_000);
} else {
  const api = 'https://api.openkey.test';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let counter = 0;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-approval-passkey-'));
    const database = new PGlite(directory);
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) {
        await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
    } finally {
      await database.close();
    }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    secret = context.secret;
    cookieName = context.authCookies.sessionToken.name;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  const call = (method: string, path: string, cookie: string, body?: unknown) => app.fetch(new Request(`${api}${path}`, {
    method,
    headers: { cookie, origin: web, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  }));

  async function signedIn() {
    const n = ++counter;
    const userId = `approval-user-${n}-${randomUUID()}`;
    const sessionId = `approval-session-${n}`;
    const token = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.session.create({ data: { id: sessionId, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    return { userId, sessionId, cookie };
  }

  async function options(cookie: string, mode: string) {
    const response = await call('POST', '/api/account/passkey-approval/options', cookie, { mode });
    expect(response.status, await response.clone().text()).toBe(200);
    return await response.json() as { challengeToken: string; options: PublicKeyCredentialRequestOptionsJSON };
  }

  describe('the setting', () => {
    test('without a passkey that counts it is SENSITIVE stored, NEVER in force, and cannot be changed', async () => {
      const { cookie } = await signedIn();
      expect(await (await call('GET', '/api/account/passkey-approval', cookie)).json())
        .toEqual({ mode: 'SENSITIVE', effectiveMode: 'NEVER', stepUpPasskeys: 0 });
      const response = await call('PATCH', '/api/account/passkey-approval', cookie, { mode: 'ALWAYS' });
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ code: 'passkey_approval_needs_passkey' });
    });

    test('asking on more approvals needs no passkey; asking on fewer needs one bound to the new mode', async () => {
      const { userId, cookie } = await signedIn();
      const passkey = await createSoftPasskey(prisma, userId, true, web);
      expect((await call('PATCH', '/api/account/passkey-approval', cookie, { mode: 'ALWAYS' })).status).toBe(200);

      const bare = await call('PATCH', '/api/account/passkey-approval', cookie, { mode: 'NEVER' });
      expect(bare.status).toBe(403);
      expect(await bare.json()).toMatchObject({ code: 'passkey_approval_required' });

      // An assertion made for another mode does not lower to this one, and its challenge is spent.
      const forSensitive = await options(cookie, 'SENSITIVE');
      const wrongMode = { challengeToken: forSensitive.challengeToken, response: passkey.assert(forSensitive.options) };
      const mismatched = await call('PATCH', '/api/account/passkey-approval', cookie, { mode: 'NEVER', passkeyAssertion: wrongMode });
      expect(await mismatched.json()).toMatchObject({ code: 'passkey_approval_invalid' });
      expect((await call('PATCH', '/api/account/passkey-approval', cookie, { mode: 'SENSITIVE', passkeyAssertion: wrongMode })).status).toBe(403);

      const forNever = await options(cookie, 'NEVER');
      const assertion = { challengeToken: forNever.challengeToken, response: passkey.assert(forNever.options) };
      const lowered = await call('PATCH', '/api/account/passkey-approval', cookie, { mode: 'NEVER', passkeyAssertion: assertion });
      expect(lowered.status, await lowered.clone().text()).toBe(200);
      expect(await lowered.json()).toMatchObject({ mode: 'NEVER', effectiveMode: 'NEVER' });
      expect((await prisma.user.findUniqueOrThrow({ where: { id: userId } })).passkeyApprovalMode).toBe('NEVER');

      // Single use: replaying the same assertion after raising again does not lower a second time.
      expect((await call('PATCH', '/api/account/passkey-approval', cookie, { mode: 'ALWAYS' })).status).toBe(200);
      const replay = await call('PATCH', '/api/account/passkey-approval', cookie, { mode: 'NEVER', passkeyAssertion: assertion });
      expect(await replay.json()).toMatchObject({ code: 'passkey_approval_invalid' });
    });

    test('a passkey enrolled on a session alone cannot confirm, nor can an assertion without user verification', async () => {
      const { userId, cookie } = await signedIn();
      await createSoftPasskey(prisma, userId, true, web);
      const sessionEnrolled = await createSoftPasskey(prisma, userId, false, web);
      const first = await options(cookie, 'NEVER');
      const refused = await call('PATCH', '/api/account/passkey-approval', cookie, {
        mode: 'NEVER', passkeyAssertion: { challengeToken: first.challengeToken, response: sessionEnrolled.assert(first.options) },
      });
      expect(refused.status).toBe(403);
      expect(await refused.json()).toMatchObject({ code: 'passkey_not_step_up_capable' });

      const owner = await createSoftPasskey(prisma, userId, true, web);
      const second = await options(cookie, 'NEVER');
      const unverified = await call('PATCH', '/api/account/passkey-approval', cookie, {
        mode: 'NEVER',
        passkeyAssertion: { challengeToken: second.challengeToken, response: owner.assert(second.options, { userVerified: false }) },
      });
      expect(await unverified.json()).toMatchObject({ code: 'passkey_approval_invalid' });
      expect((await prisma.user.findUniqueOrThrow({ where: { id: userId } })).passkeyApprovalMode).toBe('SENSITIVE');
    });
  });

  describe('the request-bound check routes run before signing', () => {
    test('SENSITIVE asks only for sensitive requests; the assertion confirms its own request, once, in its own session', async () => {
      const { userId, sessionId } = await signedIn();
      const other = await signedIn();
      const passkey = await createSoftPasskey(prisma, userId, true, web);
      const subject = { sessionId, userId };
      const binding = { purpose: 'keys_sign', requestDigest: approvalRequestDigest('personal_sign', 'hello') };

      expect(await approvalPasskeyOffer(prisma, subject, binding, 'standard')).toEqual({ required: false });
      expect(await checkApprovalPasskey(prisma, subject, binding, 'standard', undefined)).toBeNull();
      expect(await checkApprovalPasskey(prisma, subject, binding, 'sensitive', undefined))
        .toMatchObject({ code: 'passkey_approval_required' });

      const offer = await approvalPasskeyOffer(prisma, subject, binding, 'sensitive');
      if (!offer.required) throw new Error('expected a passkey offer');
      const assertion = { challengeToken: offer.challengeToken, response: passkey.assert(offer.options) };
      const otherRequest = { ...binding, requestDigest: approvalRequestDigest('personal_sign', 'goodbye') };
      expect(await checkApprovalPasskey(prisma, subject, otherRequest, 'sensitive', assertion))
        .toMatchObject({ code: 'passkey_approval_invalid' });

      const again = await approvalPasskeyOffer(prisma, subject, binding, 'sensitive');
      if (!again.required) throw new Error('expected a passkey offer');
      const fresh = { challengeToken: again.challengeToken, response: passkey.assert(again.options) };
      expect(await checkApprovalPasskey(prisma, { ...subject, sessionId: other.sessionId }, binding, 'sensitive', fresh))
        .toMatchObject({ code: 'passkey_approval_invalid' });

      const third = await approvalPasskeyOffer(prisma, subject, binding, 'sensitive');
      if (!third.required) throw new Error('expected a passkey offer');
      const good = { challengeToken: third.challengeToken, response: passkey.assert(third.options) };
      expect(await checkApprovalPasskey(prisma, subject, binding, 'sensitive', good)).toBeNull();
      expect(await checkApprovalPasskey(prisma, subject, binding, 'sensitive', good))
        .toMatchObject({ code: 'passkey_approval_invalid' });
    });

    test('an assertion from another origin is refused', async () => {
      const { userId, sessionId } = await signedIn();
      const passkey = await createSoftPasskey(prisma, userId, true, web);
      await prisma.user.update({ where: { id: userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
      const subject = { sessionId, userId };
      const binding = { purpose: 'keys_sign', requestDigest: approvalRequestDigest('personal_sign', 'hello') };
      const offer = await approvalPasskeyOffer(prisma, subject, binding, 'standard');
      if (!offer.required) throw new Error('ALWAYS asks for every approval');
      const foreign = { challengeToken: offer.challengeToken, response: passkey.assert(offer.options, { origin: 'https://evil.test' }) };
      expect(await checkApprovalPasskey(prisma, subject, binding, 'standard', foreign))
        .toMatchObject({ code: 'passkey_approval_invalid' });
    });
  });
}
