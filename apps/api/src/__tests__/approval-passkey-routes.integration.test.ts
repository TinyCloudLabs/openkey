// TC-3442: the signing and granting routes ask for the passkey the account's setting calls for, before they unseal a
// key or create a grant, against the real API on PGlite with the tracked migrations. Runs in a child process: the API
// reads its relying party, origins and database when loaded.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
import { createSoftPasskey, type SoftPasskey } from './soft-passkey';

const root = resolve(import.meta.dir, '../../../..');
const web = 'https://openkey.test';

if (process.env.OPENKEY_APPROVAL_PASSKEY_ROUTES_CHILD !== '1') {
  test('the approval routes ask for the passkey the setting calls for', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_APPROVAL_PASSKEY_ROUTES_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: web,
        CORS_ORIGIN: web,
        TINYCLOUD_BOOTSTRAP_ON_SIGN: 'off',
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
  const embedder = 'https://embedding-app.example';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let tee: typeof import('@openkey/tee');
  // No request leaves the process. The node answers only the activation of
  // the space a test names here.
  const originalFetch = globalThis.fetch;
  let hostedSpace: { host: string; spaceId: string } | null = null;

  beforeAll(async () => {
    globalThis.fetch = ((input: RequestInfo | URL) => {
      const url = String(input instanceof Request ? input.url : input);
      if (hostedSpace && url === `${hostedSpace.host}/delegate`) {
        return Promise.resolve(Response.json({ activated: [hostedSpace.spaceId] }));
      }
      return Promise.reject(new Error(`External network disabled in this test: ${url}`));
    }) as typeof fetch;
    directory = await mkdtemp(join(tmpdir(), 'openkey-approval-passkey-routes-'));
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
    tee = await import('@openkey/tee');
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    secret = context.secret;
    cookieName = context.authCookies.sessionToken.name;
  }, 120_000);

  afterAll(async () => {
    globalThis.fetch = originalFetch;
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  type Account = { userId: string; sessionId: string; token: string; cookie: string; keyId: string; address: string };

  async function account(): Promise<Account> {
    const userId = randomUUID();
    const sessionId = randomUUID();
    const token = randomBytes(32).toString('base64url');
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.session.create({ data: { id: sessionId, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    const privateKey = tee.generatePrivateKey();
    const address = tee.getAddressFromPrivateKey(privateKey);
    const sealingContext = randomBytes(32).toString('base64url');
    const sealingKey = await tee.createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    const key = await prisma.ethereumKey.create({ data: {
      userId, address, publicKey: '0x1', sealedBlob: await tee.seal(privateKey, sealingKey), sealingContext,
      keyType: 'MANAGED', isCanonicalTinyCloud: true,
    } });
    return { userId, sessionId, token, cookie, keyId: key.id, address };
  }

  const post = (path: string, auth: Record<string, string>, body: unknown, method = 'POST') => app.fetch(new Request(`${api}${path}`, {
    method,
    headers: { origin: web, 'content-type': 'application/json', ...auth },
    body: JSON.stringify(body),
  }));

  type Offer = { required: false } | { required: true; challengeToken: string; options: PublicKeyCredentialRequestOptionsJSON };

  async function offer(path: string, auth: Record<string, string>, body: unknown): Promise<Offer> {
    const response = await post(path, auth, body);
    expect(response.status, await response.clone().text()).toBe(200);
    return await response.json() as Offer;
  }

  async function assertionFor(passkey: SoftPasskey, path: string, auth: Record<string, string>, body: unknown) {
    const answer = await offer(path, auth, body);
    if (!answer.required) throw new Error(`expected ${path} to ask for the passkey`);
    return { challengeToken: answer.challengeToken, response: passkey.assert(answer.options) };
  }

  async function expectRefusal(response: Response, code: string) {
    expect(response.status, await response.clone().text()).toBe(403);
    expect(await response.json()).toMatchObject({ code });
  }

  const signIn = (address: string) => [
    'embedding-app.example wants you to sign in with your Ethereum account:',
    address,
    '',
    'Sign in',
    '',
    `URI: ${embedder}`,
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdef12345678',
    'Issued At: 2026-11-19T00:00:00.000Z',
  ].join('\n');

  const typedData = {
    domain: { name: 'Example', version: '1' },
    types: { Mail: [{ name: 'contents', type: 'string' }] },
    primaryType: 'Mail',
    message: { contents: 'hi' },
  };

  describe('message signing', () => {
    test('SENSITIVE asks for a message it cannot classify, before signing, and the passkey confirms only that message', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const auth = { cookie: owner.cookie };
      const path = `/api/keys/${owner.keyId}/sign`;

      await expectRefusal(await post(path, auth, { message: 'hello' }), 'passkey_approval_required');

      const forOther = await assertionFor(passkey, `${path}/passkey`, auth, { message: 'goodbye' });
      await expectRefusal(await post(path, auth, { message: 'hello', passkeyAssertion: forOther }), 'passkey_approval_invalid');

      const assertion = await assertionFor(passkey, `${path}/passkey`, auth, { message: 'hello' });
      const signed = await post(path, auth, { message: 'hello', passkeyAssertion: assertion });
      expect(signed.status, await signed.clone().text()).toBe(200);
      expect(await signed.json()).toMatchObject({ address: owner.address });

      // Single use.
      await expectRefusal(await post(path, auth, { message: 'hello', passkeyAssertion: assertion }), 'passkey_approval_invalid');
    });

    test('SENSITIVE signs a plain sign-in without asking; ALWAYS asks for it too', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const auth = { cookie: owner.cookie };
      const path = `/api/keys/${owner.keyId}/sign`;
      const body = { message: signIn(owner.address), requestOrigin: embedder };

      expect(await offer(`${path}/passkey`, auth, body)).toEqual({ required: false });
      expect((await post(path, auth, body)).status).toBe(200);

      await prisma.user.update({ where: { id: owner.userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
      await expectRefusal(await post(path, auth, body), 'passkey_approval_required');
      const assertion = await assertionFor(passkey, `${path}/passkey`, auth, body);
      expect((await post(path, auth, { ...body, passkeyAssertion: assertion })).status).toBe(200);
    });

    test('NEVER, or no passkey that counts, signs without asking', async () => {
      const never = await account();
      await createSoftPasskey(prisma, never.userId, true, web);
      await prisma.user.update({ where: { id: never.userId }, data: { passkeyApprovalMode: 'NEVER' } });
      expect((await post(`/api/keys/${never.keyId}/sign`, { cookie: never.cookie }, { message: 'hello' })).status).toBe(200);

      const noPasskey = await account();
      expect((await post(`/api/keys/${noPasskey.keyId}/sign`, { cookie: noPasskey.cookie }, { message: 'hello' })).status).toBe(200);
    });

    test('a passkey enrolled on a session alone cannot confirm an approval', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const sessionEnrolled = await createSoftPasskey(prisma, owner.userId, false, web);
      const auth = { cookie: owner.cookie };
      const path = `/api/keys/${owner.keyId}/sign`;
      const assertion = await assertionFor(sessionEnrolled, `${path}/passkey`, auth, { message: 'hello' });
      await expectRefusal(await post(path, auth, { message: 'hello', passkeyAssertion: assertion }), 'passkey_not_step_up_capable');
    });

    test('a confirmed approval gives the session no passkey step-up: removing a passkey still asks', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const auth = { cookie: owner.cookie };
      const path = `/api/keys/${owner.keyId}/sign`;
      const assertion = await assertionFor(passkey, `${path}/passkey`, auth, { message: 'hello' });
      expect((await post(path, auth, { message: 'hello', passkeyAssertion: assertion })).status).toBe(200);

      const session = await prisma.session.findUniqueOrThrow({ where: { id: owner.sessionId } });
      expect(session.lastPasskeyAt).toBeNull();
      expect(session.lastPasskeyId).toBeNull();
      const removal = await post('/api/auth/passkey/delete-passkey', auth, { id: passkey.id });
      expect(removal.status, await removal.clone().text()).toBe(403);
      expect(await removal.json()).toMatchObject({ code: 'PASSKEY_STEP_UP_REQUIRED' });
      expect(await prisma.passkey.count({ where: { id: passkey.id } })).toBe(1);
    });
  });

  describe('typed data', () => {
    test('SENSITIVE always asks for typed data, from the dashboard cookie and from the widget bearer alike', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const path = `/api/keys/${owner.keyId}/sign-typed-data`;

      const auths: Record<string, string>[] = [{ cookie: owner.cookie }, { authorization: `Bearer ${owner.token}` }];
      for (const auth of auths) {
        await expectRefusal(await post(path, auth, typedData), 'passkey_approval_required');
        const otherData = { ...typedData, message: { contents: 'bye' } };
        const forOther = await assertionFor(passkey, `${path}/passkey`, auth, otherData);
        await expectRefusal(await post(path, auth, { ...typedData, passkeyAssertion: forOther }), 'passkey_approval_invalid');
        const assertion = await assertionFor(passkey, `${path}/passkey`, auth, typedData);
        const signed = await post(path, auth, { ...typedData, passkeyAssertion: assertion });
        expect(signed.status, await signed.clone().text()).toBe(200);
        expect(await signed.json()).toMatchObject({ address: owner.address });
      }
    });
  });

  describe('grants that let a site or app sign later without a button', () => {
    test('a Nostr signing grant asks for the passkey for exactly its site, kinds and lifetime', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const pubkeyHex = randomBytes(32).toString('hex');
      const key = await prisma.nostrKey.create({ data: {
        userId: owner.userId, pubkeyHex, npub: `npub-${pubkeyHex}`, sealedSecret: 'unused-by-grants',
        sealingContext: randomBytes(32).toString('base64url'),
      } });
      const auth = { cookie: owner.cookie };
      const path = `/api/keys/nostr/${key.id}/grants`;
      const grant = { clientOrigin: embedder, kinds: [9], ttlSeconds: 600 };

      await expectRefusal(await post(path, auth, grant), 'passkey_approval_required');
      const longer = await assertionFor(passkey, `${path}/passkey`, auth, { ...grant, ttlSeconds: 3600 });
      await expectRefusal(await post(path, auth, { ...grant, passkeyAssertion: longer }), 'passkey_approval_invalid');
      expect(await prisma.nostrSigningGrant.count({ where: { userId: owner.userId } })).toBe(0);

      const assertion = await assertionFor(passkey, `${path}/passkey`, auth, grant);
      const created = await post(path, auth, { ...grant, passkeyAssertion: assertion });
      expect(created.status, await created.clone().text()).toBe(201);
      expect(await prisma.nostrSigningGrant.count({ where: { userId: owner.userId } })).toBe(1);
    });

    test('TinyCloud signing: turning it on asks, turning it off never does', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const auth = { cookie: owner.cookie };
      const policyEpoch = async () => Number((await prisma.user.findUniqueOrThrow({ where: { id: owner.userId } })).tinyCloudManageKeyPolicyEpoch);
      const epoch = await policyEpoch();

      const enableApp = { enabled: true, expectedEpoch: epoch, confirmation: 'TAKE CONTROL' };
      await expectRefusal(await post('/api/account/tinycloud-apps/some-app', auth, enableApp, 'PATCH'), 'passkey_approval_required');
      const disableApp = await post('/api/account/tinycloud-apps/some-app', auth, { ...enableApp, enabled: false }, 'PATCH');
      expect(await disableApp.text()).not.toContain('passkey_');
      expect(await offer('/api/account/tinycloud-apps/some-app/passkey', auth, { enabled: false, expectedEpoch: epoch }))
        .toEqual({ required: false });

      const shared = { mode: 'USER_CONTROLLED_SHARED', expectedEpoch: epoch, confirmation: 'TAKE CONTROL' };
      await expectRefusal(await post('/api/account/tinycloud-manage-key', auth, shared, 'PATCH'), 'passkey_approval_required');
      const assertion = await assertionFor(passkey, '/api/account/tinycloud-manage-key/passkey', auth,
        { mode: shared.mode, expectedEpoch: epoch });
      const changed = await post('/api/account/tinycloud-manage-key', auth, { ...shared, passkeyAssertion: assertion }, 'PATCH');
      expect(changed.status, await changed.clone().text()).toBe(200);
      expect((await prisma.user.findUniqueOrThrow({ where: { id: owner.userId } })).tinyCloudManageKeyMode).toBe('USER_CONTROLLED_SHARED');

      const exclusive = await post('/api/account/tinycloud-manage-key', auth,
        { mode: 'USER_CONTROLLED_EXCLUSIVE', expectedEpoch: await policyEpoch(), confirmation: 'TAKE CONTROL' }, 'PATCH');
      expect(exclusive.status, await exclusive.clone().text()).toBe(200);
    });
  });

  describe('POST /api/delegate', () => {
    const permissions = [
      { service: 'tinycloud.kv', space: 'synthetic-proof', path: 'notes', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
      { service: 'tinycloud.capabilities', space: 'synthetic-proof', path: '', actions: ['tinycloud.capabilities/read'] },
    ];
    const delegateBody = (owner: Account) => {
      const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
      return { keyId: owner.keyId, jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, host: 'https://node.example.test', permissions, expiry: '3600s' };
    };
    type Prepared = {
      prepared: { siwe: string };
      authorizationContext: { token: string };
      selectedActionKeys: string[];
      passkey: Offer;
    };
    async function prepare(owner: Account, body: ReturnType<typeof delegateBody>) {
      const response = await post('/api/delegate/prepare', { cookie: owner.cookie }, body);
      expect(response.status, await response.clone().text()).toBe(200);
      const prepared = await response.json() as Prepared;
      const approval = {
        ...body, protocolVersion: 1, prepared: prepared.prepared,
        authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys,
      };
      return { approval, passkey: prepared.passkey };
    }

    test('the preview carries the challenge for its bytes; Approve without it spends nothing, and with it signs', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      await prisma.user.update({ where: { id: owner.userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
      const auth = { cookie: owner.cookie };
      const first = await prepare(owner, delegateBody(owner));
      const second = await prepare(owner, delegateBody(owner));
      if (!first.passkey.required || !second.passkey.required) throw new Error('ALWAYS asks for every approval');

      await expectRefusal(await post('/api/delegate', auth, first.approval), 'passkey_approval_required');
      // The challenge from another preview does not confirm these bytes.
      const forSecond = { challengeToken: second.passkey.challengeToken, response: passkey.assert(second.passkey.options) };
      await expectRefusal(await post('/api/delegate', auth, { ...first.approval, passkeyAssertion: forSecond }), 'passkey_approval_invalid');

      const assertion = { challengeToken: first.passkey.challengeToken, response: passkey.assert(first.passkey.options) };
      const approved = await post('/api/delegate', auth, { ...first.approval, passkeyAssertion: assertion });
      expect(approved.status, await approved.clone().text()).toBe(200);
      expect(await approved.json()).toMatchObject({ siwe: first.approval.prepared.siwe });
    });

    test('SENSITIVE approves standard access without asking', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const { approval, passkey } = await prepare(owner, delegateBody(owner));
      expect(passkey).toEqual({ required: false });
      const approved = await post('/api/delegate', { cookie: owner.cookie }, approval);
      expect(approved.status, await approved.clone().text()).toBe(200);
    });
  });

  describe('POST /api/delegate/authorize-sign', () => {
    async function prepareContext(owner: Account) {
      const { prepareSession } = await import('@tinycloud/node-sdk-wasm');
      const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
      const sessionJwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
      const spaceId = `tinycloud:pkh:eip155:1:${owner.address}:default`;
      const now = new Date();
      const { siwe } = prepareSession({
        address: owner.address, chainId: 1, domain: 'openkey.test', issuedAt: now.toISOString(),
        expirationTime: new Date(now.getTime() + 3_600_000).toISOString(), spaceId, jwk: sessionJwk,
        abilities: { kv: { [spaceId]: ['tinycloud.kv/get'] }, capabilities: { [spaceId]: ['tinycloud.capabilities/read'] } },
      } as Parameters<typeof prepareSession>[0]);
      const prepared = await post('/api/delegate/authorize-sign-prepare', { cookie: owner.cookie },
        { keyId: owner.keyId, siwe, jwk: sessionJwk, host: 'https://node.example.test', requestOrigin: web });
      expect(prepared.status, await prepared.clone().text()).toBe(200);
      return await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
    }
    async function previewOf(owner: Account, context: { authorizationContextToken: string; allowedActionIds: string[] }) {
      const { authorizationContextToken, allowedActionIds } = context;
      const previewed = await post('/api/delegate/authorize-sign-preview', { cookie: owner.cookie },
        { authorizationContextToken, selectedActionIds: allowedActionIds });
      expect(previewed.status, await previewed.clone().text()).toBe(200);
      const body = await previewed.json() as { previewApprovalToken: string; signedMessage: string; passkey: Offer };
      return {
        passkey: body.passkey,
        approval: {
          authorizationContextToken, previewApprovalToken: body.previewApprovalToken,
          selectedActionIds: allowedActionIds, protocolVersion: 1,
        },
        signedMessage: body.signedMessage,
      };
    }
    const preview = async (owner: Account) => previewOf(owner, await prepareContext(owner));

    test('the preview carries the challenge for its bytes; Approve without it spends nothing, and with it signs', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      await prisma.user.update({ where: { id: owner.userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
      const auth = { cookie: owner.cookie };
      const first = await preview(owner);
      const second = await preview(owner);
      if (!first.passkey.required || !second.passkey.required) throw new Error('ALWAYS asks for every approval');

      await expectRefusal(await post('/api/delegate/authorize-sign', auth, first.approval), 'passkey_approval_required');
      const forSecond = { challengeToken: second.passkey.challengeToken, response: passkey.assert(second.passkey.options) };
      await expectRefusal(await post('/api/delegate/authorize-sign', auth, { ...first.approval, passkeyAssertion: forSecond }),
        'passkey_approval_invalid');

      const assertion = { challengeToken: first.passkey.challengeToken, response: passkey.assert(first.passkey.options) };
      const signed = await post('/api/delegate/authorize-sign', auth, { ...first.approval, passkeyAssertion: assertion });
      expect(signed.status, await signed.clone().text()).toBe(200);
      expect(await signed.json()).toMatchObject({ signedMessage: first.signedMessage });
    });

    test('a passkey confirms one preview: a re-preview of the same request needs its own', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      await prisma.user.update({ where: { id: owner.userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
      const auth = { cookie: owner.cookie };
      const context = await prepareContext(owner);
      const first = await previewOf(owner, context);
      const again = await previewOf(owner, context);
      if (!first.passkey.required || !again.passkey.required) throw new Error('ALWAYS asks for every approval');
      expect(again.signedMessage).toBe(first.signedMessage);

      const forFirst = { challengeToken: first.passkey.challengeToken, response: passkey.assert(first.passkey.options) };
      await expectRefusal(await post('/api/delegate/authorize-sign', auth, { ...again.approval, passkeyAssertion: forFirst }),
        'passkey_approval_invalid');
      const forAgain = { challengeToken: again.passkey.challengeToken, response: passkey.assert(again.passkey.options) };
      const signed = await post('/api/delegate/authorize-sign', auth, { ...again.approval, passkeyAssertion: forAgain });
      expect(signed.status, await signed.clone().text()).toBe(200);
    });

    test('SENSITIVE signs standard access without asking', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const { passkey, approval } = await preview(owner);
      expect(passkey).toEqual({ required: false });
      const signed = await post('/api/delegate/authorize-sign', { cookie: owner.cookie }, approval);
      expect(signed.status, await signed.clone().text()).toBe(200);
    });
  });

  describe('native app consent', () => {
    const appId = 'xyz.tinycloud.passkeytest';
    // A trusted node host. The account's space there is already set up, and
    // the fetch guard answers its activation.
    const host = 'https://tee.node.tinycloud.xyz';
    afterAll(() => { hostedSpace = null; });

    async function nativeRequest(owner: Account) {
      const clientId = `ok_${randomBytes(16).toString('hex')}`;
      await prisma.oauthClient.create({ data: {
        id: randomUUID(), clientId, name: 'Native fixture', public: true, type: 'native', tokenEndpointAuthMethod: 'none',
        redirectUris: ['xyz.tinycloud.passkeytest://callback'], scopes: ['openid', 'tinycloud:delegation'], contacts: [],
        tinycloudNativeDelegation: {
          version: 1, appId, tinycloudHost: host, kv: { paths: [`${appId}/notes/`], actions: ['get', 'list'] },
          maxDelegationTtlSeconds: 3600, grantLifetimeSeconds: 86_400, siweDomain: 'openkey.so',
        },
      } });
      await prisma.tinyCloudBootstrapState.create({ data: {
        userId: owner.userId, keyId: owner.keyId, address: owner.address, chainId: 1, tinycloudHost: host,
        bootstrapVersion: 'test', status: 'complete', checkedAt: new Date(), completedAt: new Date(),
      } });
      hostedSpace = { host, spaceId: `tinycloud:pkh:eip155:1:${owner.address}:applications` };
      const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
      const sessionJwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x! };
      const { reviewerSessionDid } = await import('../services/reviewer-delegation');
      const id = randomBytes(16).toString('hex');
      await prisma.tinyCloudNativeRequest.create({ data: {
        id, clientId, redirectUri: 'xyz.tinycloud.passkeytest://callback', state: 'state', codeChallenge: 'challenge',
        scopes: ['openid', 'tinycloud:delegation'], sessionDid: reviewerSessionDid(sessionJwk)!, sessionJwk,
        sessionJkt: randomBytes(32).toString('base64url'),
        requestedPermissions: [
          { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
          { service: 'tinycloud.kv', space: 'applications', path: `${appId}/notes/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
        ],
        ttlSeconds: 3600, status: 'RESOLVED', userId: owner.userId,
        requestUriExpiresAt: new Date(Date.now() + 600_000), expiresAt: new Date(Date.now() + 600_000),
      } });
      return `/api/oauth/tinycloud/requests/${id}`;
    }

    type NativePreview = { revision: number; digest: string; sessionSiwe: string; passkey: Offer };
    async function preview(owner: Account, path: string) {
      const prepared = await post(`${path}/prepare`, { cookie: owner.cookie }, {});
      expect(prepared.status, await prepared.clone().text()).toBe(200);
      const body = await prepared.json() as NativePreview;
      return { passkey: body.passkey, approval: { revision: body.revision, digest: body.digest, sessionSiwe: body.sessionSiwe } };
    }

    test('the preview carries the challenge for its revision; Approve without it signs nothing, and with it approves', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      await prisma.user.update({ where: { id: owner.userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
      const path = await nativeRequest(owner);
      const auth = { cookie: owner.cookie };
      const { passkey: offered, approval } = await preview(owner, path);
      if (!offered.required) throw new Error('ALWAYS asks for every approval');

      await expectRefusal(await post(`${path}/approve`, auth, approval), 'passkey_approval_required');
      const id = path.split('/').at(-1)!;
      expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).signature).toBeNull();

      const assertion = { challengeToken: offered.challengeToken, response: passkey.assert(offered.options) };
      const approved = await post(`${path}/approve`, auth, { ...approval, passkeyAssertion: assertion });
      expect(approved.status, await approved.clone().text()).toBe(200);
      expect(await approved.json()).toMatchObject({ status: 'APPROVED', hosting: 'existing' });
      expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).status).toBe('APPROVED');
    });

    test('SENSITIVE approves standard access without asking', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const path = await nativeRequest(owner);
      const { passkey, approval } = await preview(owner, path);
      expect(passkey).toEqual({ required: false });
      const approved = await post(`${path}/approve`, { cookie: owner.cookie }, approval);
      expect(approved.status, await approved.clone().text()).toBe(200);
      expect(await approved.json()).toMatchObject({ status: 'APPROVED', hosting: 'existing' });
    });
  });
}
