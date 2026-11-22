// One passkey per web sign interaction: a passkey sign-in made for a web sign flow (the id the sign pop-up or iframe
// draws and names in `x-openkey-passkey-flow`) covers that flow's Approve, against the real API on PGlite with the
// tracked migrations. Runs in a child process: the API reads its relying party, origins and database when loaded.
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

if (process.env.OPENKEY_WEB_FLOW_PASSKEY_CHILD !== '1') {
  test('a passkey sign-in covers the Approve of the web sign flow it was made for', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_WEB_FLOW_PASSKEY_CHILD: '1',
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
  const FLOW_HEADER = 'x-openkey-passkey-flow';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let tee: typeof import('@openkey/tee');
  const originalFetch = globalThis.fetch;

  beforeAll(async () => {
    globalThis.fetch = ((input: RequestInfo | URL) => {
      const url = String(input instanceof Request ? input.url : input);
      return Promise.reject(new Error(`External network disabled in this test: ${url}`));
    }) as typeof fetch;
    directory = await mkdtemp(join(tmpdir(), 'openkey-web-flow-passkey-'));
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

  type Account = { userId: string; sessionId: string; cookie: string; keyId: string; address: string };

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
    return { userId, sessionId, cookie, keyId: key.id, address };
  }

  const newFlowId = () => `w.${randomBytes(24).toString('base64url')}`;
  const post = (path: string, auth: Record<string, string>, body: unknown, method = 'POST', headers: Record<string, string> = {}) =>
    app.fetch(new Request(`${api}${path}`, {
      method,
      headers: { origin: web, 'content-type': 'application/json', ...auth, ...headers },
      body: JSON.stringify(body),
    }));
  const flow = (id: string | null): Record<string, string> => (id ? { [FLOW_HEADER]: id } : {});

  async function expectRefusal(response: Response, code: string) {
    expect(response.status, await response.clone().text()).toBe(403);
    expect(await response.json()).toMatchObject({ code });
  }

  const cookieHeader = (response: Response) => response.headers.getSetCookie().map((cookie) => cookie.split(';')[0]).join('; ');
  const flowRows = (userId: string) => prisma.verification.count({ where: { userId, identifier: { startsWith: 'openkey-flow-passkey:' } } });

  /** The sign-in the pop-up makes: Better Auth's passkey routes with the session cookie. `id` is the flow header. */
  async function popupSignIn(passkey: SoftPasskey, id: string | null, extra: { userVerified?: boolean } = {}) {
    const asked = await app.fetch(new Request(`${api}/api/auth/passkey/generate-authenticate-options`, { headers: { origin: web } }));
    expect(asked.status, await asked.clone().text()).toBe(200);
    const options = await asked.json() as PublicKeyCredentialRequestOptionsJSON;
    const response = await app.fetch(new Request(`${api}/api/auth/passkey/verify-authentication`, {
      method: 'POST',
      headers: { origin: web, 'content-type': 'application/json', cookie: cookieHeader(asked), ...flow(id) },
      body: JSON.stringify({ response: passkey.assert(options, extra) }),
    }));
    expect(response.status, await response.clone().text()).toBe(200);
    const session = (await response.clone().json() as { session: { id: string } }).session;
    return { auth: { cookie: cookieHeader(response) }, sessionId: session.id };
  }

  /** The sign-in the iframe makes: the token proxy, then the session token as a bearer. Returns the proxy's answer too. */
  async function iframeAttempt(passkey: SoftPasskey, id: string | null, extra: { userVerified?: boolean } = {}) {
    const asked = await post('/api/passkey/generate-authenticate-options', {}, {});
    expect(asked.status, await asked.clone().text()).toBe(200);
    const { challengeToken, ...options } = await asked.json() as PublicKeyCredentialRequestOptionsJSON & { challengeToken: string };
    return post('/api/passkey/verify-authentication', {}, { response: passkey.assert(options, extra), challengeToken }, 'POST', flow(id));
  }
  async function iframeSignIn(passkey: SoftPasskey, id: string | null) {
    const response = await iframeAttempt(passkey, id);
    expect(response.status, await response.clone().text()).toBe(200);
    const body = await response.json() as { sessionToken: string; session: { id: string } };
    return { auth: { authorization: `Bearer ${body.sessionToken}` }, sessionId: body.session.id };
  }

  async function prepareContext(owner: Account, auth: Record<string, string>) {
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
    const prepared = await post('/api/delegate/authorize-sign-prepare', auth,
      { keyId: owner.keyId, siwe, jwk: sessionJwk, host: 'https://node.example.test', requestOrigin: web });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    return await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
  }

  type Offer = { required: false; flowCover?: true } | { required: true; challengeToken: string; options: PublicKeyCredentialRequestOptionsJSON };

  async function previewOf(auth: Record<string, string>, context: { authorizationContextToken: string; allowedActionIds: string[] }, id: string | null) {
    const { authorizationContextToken, allowedActionIds } = context;
    const previewed = await post('/api/delegate/authorize-sign-preview', auth,
      { authorizationContextToken, selectedActionIds: allowedActionIds }, 'POST', flow(id));
    expect(previewed.status, await previewed.clone().text()).toBe(200);
    const body = await previewed.json() as { previewApprovalToken: string; signedMessage: string; passkey: Offer };
    return {
      passkey: body.passkey,
      approval: { authorizationContextToken, previewApprovalToken: body.previewApprovalToken, selectedActionIds: allowedActionIds, protocolVersion: 1 },
      signedMessage: body.signedMessage,
    };
  }
  const authorize = (auth: Record<string, string>, approval: unknown, id: string | null) =>
    post('/api/delegate/authorize-sign', auth, approval, 'POST', flow(id));

  async function alwaysAsking() {
    const owner = await account();
    const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
    await prisma.user.update({ where: { id: owner.userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
    return { owner, passkey };
  }

  describe('the sign pop-up and iframe passkey sign-in', () => {
    for (const [name, signIn] of [['pop-up (cookie session)', popupSignIn], ['iframe (token proxy and bearer)', iframeSignIn]] as const) {
      test(`${name}: the sign-in covers that flow's preview and Approve once, and ends with the approval`, async () => {
        const { owner, passkey } = await alwaysAsking();
        const id = newFlowId();
        const signedIn = await signIn(passkey, id);
        expect(await flowRows(owner.userId)).toBe(1);
        const row = await prisma.verification.findFirstOrThrow({ where: { userId: owner.userId, identifier: { startsWith: 'openkey-flow-passkey:' } } });
        expect(row.identifier).toBe(`openkey-flow-passkey:${signedIn.sessionId}:${id}`);
        const recordedExpiry = row.expiresAt.getTime();
        expect(recordedExpiry - Date.now()).toBeGreaterThan(4 * 60_000);
        expect(recordedExpiry - Date.now()).toBeLessThanOrEqual(5 * 60_000);

        const context = await prepareContext(owner, signedIn.auth);
        const first = await previewOf(signedIn.auth, context, id);
        expect(first.passkey).toEqual({ required: false, flowCover: true });
        // A new preview (a changed selection) is covered too and does not extend the five minutes.
        const again = await previewOf(signedIn.auth, context, id);
        expect(again.passkey).toEqual({ required: false, flowCover: true });
        expect((await prisma.verification.findFirstOrThrow({ where: { id: row.id } })).expiresAt.getTime()).toBe(recordedExpiry);

        const signed = await authorize(signedIn.auth, again.approval, id);
        expect(signed.status, await signed.clone().text()).toBe(200);
        expect(await signed.json()).toMatchObject({ signedMessage: again.signedMessage });
        // Consumed: the cover ends with the approval, so the next request in the flow asks.
        expect(await flowRows(owner.userId)).toBe(0);
        expect((await previewOf(signedIn.auth, await prepareContext(owner, signedIn.auth), id)).passkey.required).toBe(true);
      });
    }

    test('the exact-byte path: the offer and the signature are covered for that flow, once', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const path = `/api/keys/${owner.keyId}/sign`;
      const body = { message: 'hello', requestOrigin: embedder };

      const offered = await post(`${path}/passkey`, signedIn.auth, body, 'POST', flow(id));
      expect(await offered.json()).toEqual({ required: false, flowCover: true });
      const uncovered = await post(`${path}/passkey`, signedIn.auth, body);
      expect((await uncovered.json() as Offer).required).toBe(true);

      await expectRefusal(await post(path, signedIn.auth, body), 'passkey_approval_required');
      expect(await flowRows(owner.userId)).toBe(1);
      const signed = await post(path, signedIn.auth, body, 'POST', flow(id));
      expect(signed.status, await signed.clone().text()).toBe(200);
      expect(await signed.json()).toMatchObject({ address: owner.address });
      expect(await flowRows(owner.userId)).toBe(0);
      await expectRefusal(await post(path, signedIn.auth, body, 'POST', flow(id)), 'passkey_approval_required');
    });

    test('the account setting still decides: NEVER needs no passkey and SENSITIVE needs none for standard access', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const preview = await previewOf(signedIn.auth, await prepareContext(owner, signedIn.auth), id);
      expect(preview.passkey).toEqual({ required: false });
      // A SENSITIVE message the cover does not exist for still asks: a different flow id is no cover.
      const exact = await post(`/api/keys/${owner.keyId}/sign`, signedIn.auth, { message: 'hello' }, 'POST', flow(newFlowId()));
      await expectRefusal(exact, 'passkey_approval_required');
    });
  });

  describe('what a cover applies to', () => {
    test('that session and that flow id only: another session, another flow id, no header, a body or query value, a native-shaped id', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const otherSession = { cookie: owner.cookie };
      expect(signedIn.sessionId).not.toBe(owner.sessionId);

      // Session A's cover is refused for session B of the same user with the same flow id.
      expect((await previewOf(otherSession, await prepareContext(owner, otherSession), id)).passkey.required).toBe(true);
      const forB = await previewOf(otherSession, await prepareContext(owner, otherSession), id);
      await expectRefusal(await authorize(otherSession, forB.approval, id), 'passkey_approval_required');

      const context = await prepareContext(owner, signedIn.auth);
      // Another flow id, no header, and the id in the body or the query string.
      expect((await previewOf(signedIn.auth, context, newFlowId())).passkey.required).toBe(true);
      expect((await previewOf(signedIn.auth, context, null)).passkey.required).toBe(true);
      const inBody = await post('/api/delegate/authorize-sign-preview', signedIn.auth,
        { authorizationContextToken: context.authorizationContextToken, selectedActionIds: context.allowedActionIds, flowId: id, passkeyFlow: id });
      expect(((await inBody.json()) as { passkey: Offer }).passkey.required).toBe(true);
      const inQuery = await post(`/api/delegate/authorize-sign-preview?flow=${id}&x-openkey-passkey-flow=${id}`, signedIn.auth,
        { authorizationContextToken: context.authorizationContextToken, selectedActionIds: context.allowedActionIds });
      expect(((await inQuery.json()) as { passkey: Offer }).passkey.required).toBe(true);
      // A native-shaped id names no web flow, even with a row recorded under it.
      const nativeShaped = randomBytes(24).toString('base64url');
      await prisma.verification.create({ data: {
        id: randomUUID(), identifier: `openkey-flow-passkey:${signedIn.sessionId}:${nativeShaped}`, userId: owner.userId,
        value: passkey.id, expiresAt: new Date(Date.now() + 60_000),
      } });
      expect((await previewOf(signedIn.auth, context, nativeShaped)).passkey.required).toBe(true);
      // The control: the same session and flow id.
      expect((await previewOf(signedIn.auth, context, id)).passkey).toEqual({ required: false, flowCover: true });
    });

    test('five minutes from the assertion: an expired cover asks again, and previews do not extend it', async () => {
      const { flowPasskeyCovers, recordFlowPasskey } = await import('../services/approval-passkey');
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const id = newFlowId();
      const subject = { userId: owner.userId, sessionId: randomUUID() };
      const at = new Date();
      expect(await recordFlowPasskey(prisma, { ...subject, flowId: id, credentialId: passkey.credentialID, userVerified: true }, at)).toBe(true);
      expect(await flowPasskeyCovers(prisma, subject, id, new Date(at.getTime() + 4 * 60_000))).toBe(true);
      expect(await flowPasskeyCovers(prisma, subject, id, new Date(at.getTime() + 5 * 60_000 + 1_000))).toBe(false);
      expect(await flowPasskeyCovers(prisma, { ...subject, userId: randomUUID() }, id, at)).toBe(false);
      expect(await flowPasskeyCovers(prisma, { ...subject, sessionId: null }, id, at)).toBe(false);

      // An expired row: the route asks for the passkey again.
      const { owner: asker, passkey: askerKey } = await alwaysAsking();
      const flowId = newFlowId();
      const signedIn = await popupSignIn(askerKey, flowId);
      await prisma.verification.updateMany({
        where: { userId: asker.userId, identifier: { startsWith: 'openkey-flow-passkey:' } }, data: { expiresAt: new Date(Date.now() - 1_000) },
      });
      const preview = await previewOf(signedIn.auth, await prepareContext(asker, signedIn.auth), flowId);
      expect(preview.passkey.required).toBe(true);
      await expectRefusal(await authorize(signedIn.auth, preview.approval, flowId), 'passkey_approval_required');
    });

    test('a sign-in records nothing without a user-verified step-up passkey, a session, and a well-formed web id', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const valid = randomBytes(24).toString('base64url');
      // No header, a malformed one, a native-shaped one with no request, wrong prefix, case, length, characters.
      for (const bad of [null, 'x:y', valid, `W.${valid}`, `w.${valid.slice(1)}`, `w.${valid}a`, `w:${valid}`, `w.${valid.slice(1)}!`, `w.${valid.slice(1)}:`, `w.${valid.slice(1)} `]) {
        await popupSignIn(passkey, bad);
        await iframeSignIn(passkey, bad);
        expect(await flowRows(owner.userId), String(bad)).toBe(0);
      }
      // An assertion without user verification.
      await popupSignIn(passkey, newFlowId(), { userVerified: false });
      // The token proxy refuses an assertion that was not user-verified, so no session is issued either.
      expect((await iframeAttempt(passkey, newFlowId(), { userVerified: false })).status).toBe(400);
      expect(await flowRows(owner.userId)).toBe(0);
      // A passkey enrolled on a session alone does not count for step-up.
      const weak = await account();
      const weakPasskey = await createSoftPasskey(prisma, weak.userId, false, web);
      await popupSignIn(weakPasskey, newFlowId());
      await iframeSignIn(weakPasskey, newFlowId());
      expect(await flowRows(weak.userId)).toBe(0);
      // A response that issued no session records nothing.
      const { recordFlowPasskeyAfterHook } = await import('../services/approval-passkey');
      await recordFlowPasskeyAfterHook(prisma, { error: 'no session' }, newFlowId(), { response: { id: passkey.credentialID } });
      await recordFlowPasskeyAfterHook(prisma, new Response('{}', { status: 401 }), newFlowId(), { response: { id: passkey.credentialID } });
      expect(await flowRows(owner.userId)).toBe(0);
      // The control.
      await popupSignIn(passkey, newFlowId());
      await iframeSignIn(passkey, newFlowId());
      expect(await flowRows(owner.userId)).toBe(2);
    });

    test('a native flow keeps its own shape: a web id never reaches the request row, and a request id is no web id', async () => {
      const { recordFlowPasskey } = await import('../services/approval-passkey');
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const subject = { userId: owner.userId, sessionId: randomUUID(), credentialId: passkey.credentialID, userVerified: true };
      expect(await recordFlowPasskey(prisma, { ...subject, flowId: randomBytes(24).toString('base64url') })).toBe(false);
      expect(await recordFlowPasskey(prisma, { ...subject, flowId: newFlowId() })).toBe(true);
    });
  });

  describe('the approval is still the preview\'s approval', () => {
    test('a covered Approve for another preview, another user or after it was spent is refused', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const one = await previewOf(signedIn.auth, await prepareContext(owner, signedIn.auth), id);
      const two = await previewOf(signedIn.auth, await prepareContext(owner, signedIn.auth), id);

      // The digest of another preview's bytes: the approval token of `two` does not approve `one`'s context.
      const crossed = await authorize(signedIn.auth, { ...one.approval, previewApprovalToken: two.approval.previewApprovalToken }, id);
      expect(crossed.status, await crossed.clone().text()).not.toBe(200);
      // Another user holding the tokens cannot use them, with or without the flow id.
      const stranger = await account();
      const strangerKey = await createSoftPasskey(prisma, stranger.userId, true, web);
      await prisma.user.update({ where: { id: stranger.userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
      const strangerSession = await popupSignIn(strangerKey, newFlowId());
      const stolen = await authorize(strangerSession.auth, one.approval, id);
      expect(stolen.status, await stolen.clone().text()).not.toBe(200);
      // Tampered selection: the preview sealed which actions are approved.
      const widened = await authorize(signedIn.auth, { ...two.approval, selectedActionIds: [...two.approval.selectedActionIds, 'tinycloud.kv/put:x'] }, id);
      expect(widened.status, await widened.clone().text()).not.toBe(200);

      const signed = await authorize(signedIn.auth, two.approval, id);
      expect(signed.status, await signed.clone().text()).toBe(200);
      // Single use: the same tokens never sign twice, covered or not.
      const replay = await authorize(signedIn.auth, two.approval, id);
      expect(replay.status).not.toBe(200);
      expect(await flowRows(owner.userId)).toBe(0);
    });

    test('cancelling ends the cover for the calling session and that flow only', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const other = await popupSignIn(passkey, id);
      expect(await flowRows(owner.userId)).toBe(2);

      // Another flow id, a malformed value and another session's call end nothing of this session's.
      for (const value of [newFlowId(), 'x', randomBytes(24).toString('base64url'), null]) {
        const released = await post('/api/delegate/authorize-sign-release', signedIn.auth, {}, 'POST', flow(value));
        expect(released.status, await released.clone().text()).toBe(200);
        expect(await flowRows(owner.userId)).toBe(2);
      }
      const released = await post('/api/delegate/authorize-sign-release', signedIn.auth, {}, 'POST', flow(id));
      expect(released.status, await released.clone().text()).toBe(200);
      expect(await flowRows(owner.userId)).toBe(1);
      expect(await prisma.verification.count({ where: { identifier: `openkey-flow-passkey:${other.sessionId}:${id}` } })).toBe(1);

      const preview = await previewOf(signedIn.auth, await prepareContext(owner, signedIn.auth), id);
      expect(preview.passkey.required).toBe(true);
      await expectRefusal(await authorize(signedIn.auth, preview.approval, id), 'passkey_approval_required');
      // Nobody without a session releases anything.
      const anonymous = await post('/api/delegate/authorize-sign-release', {}, {}, 'POST', flow(id));
      expect(anonymous.status).toBe(401);
      expect(await flowRows(owner.userId)).toBe(1);
    });
  });

  describe('everything else keeps its own passkey', () => {
    test('the account actions that always ask ignore a live cover, for both sign-in paths', async () => {
      const { owner, passkey } = await alwaysAsking();
      await prisma.user.update({ where: { id: owner.userId }, data: { passkeyApprovalMode: 'SENSITIVE' } });
      for (const [name, signIn] of [['pop-up', popupSignIn], ['iframe', iframeSignIn]] as const) {
        const signedIn = await signIn(passkey, newFlowId());
        const auth = signedIn.auth;
        const epoch = Number((await prisma.user.findUniqueOrThrow({ where: { id: owner.userId } })).tinyCloudManageKeyPolicyEpoch);

        // TinyCloud signing controls and the approval setting are refused to a bearer outright; the cookie session
        // reaches the passkey check.
        if (name === 'pop-up') {
          await expectRefusal(await post('/api/account/tinycloud-apps/some-app', auth,
            { enabled: true, expectedEpoch: epoch, confirmation: 'TAKE CONTROL' }, 'PATCH'), 'passkey_approval_required');
          await expectRefusal(await post('/api/account/tinycloud-manage-key', auth,
            { mode: 'USER_CONTROLLED_SHARED', expectedEpoch: epoch, confirmation: 'TAKE CONTROL' }, 'PATCH'), 'passkey_approval_required');
          await expectRefusal(await post('/api/account/passkey-approval', auth, { mode: 'NEVER' }, 'PATCH'), 'passkey_approval_required');
        }
        await expectRefusal(await post(`/api/keys/${owner.keyId}/sign-typed-data`, auth, {
          domain: { name: 'Example', version: '1' }, types: { Mail: [{ name: 'contents', type: 'string' }] },
          primaryType: 'Mail', message: { contents: 'hi' },
        }), 'passkey_approval_required');
      }
      expect((await prisma.user.findUniqueOrThrow({ where: { id: owner.userId } })).passkeyApprovalMode).toBe('SENSITIVE');
    });

    test('account deletion, passkey enrolment and removal ask for a fresh step-up with a live cover', async () => {
      const { owner, passkey } = await alwaysAsking();
      const signedIn = await popupSignIn(passkey, newFlowId());
      expect(await flowRows(owner.userId)).toBe(1);
      const auth = signedIn.auth;
      await expectRefusal(await post('/api/account/delete', auth, { confirmation: 'DELETE MY ACCOUNT' }, 'POST', flow(newFlowId())), 'passkey_step_up_required');
      const removal = await post('/api/auth/passkey/delete-passkey', auth, { id: passkey.id });
      expect(removal.status, await removal.clone().text()).toBe(403);
      expect(await removal.json()).toMatchObject({ code: 'PASSKEY_STEP_UP_REQUIRED' });
      const enrolment = await app.fetch(new Request(`${api}/api/auth/passkey/generate-register-options`, {
        headers: { origin: web, ...auth },
      }));
      expect(enrolment.status, await enrolment.clone().text()).toBe(403);
      expect(await enrolment.json()).toMatchObject({ code: 'PASSKEY_STEP_UP_REQUIRED' });
      expect(await prisma.passkey.count({ where: { id: passkey.id } })).toBe(1);
      expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
    });

    test('only the web sign routes and the native consent routes read a cover', async () => {
      const files = [
        ...(await readdir(join(root, 'apps/api/src/routes'), { recursive: true })).filter((name) => name.endsWith('.ts')).map((name) => join('routes', name)),
        ...(await readdir(join(root, 'apps/api/src/services'), { recursive: true })).filter((name) => name.endsWith('.ts')).map((name) => join('services', name)),
      ];
      const readers: Record<string, number> = {};
      for (const file of files) {
        const source = await readFile(join(root, 'apps/api/src', file), 'utf8');
        const count = (source.match(/\b(checkApprovalPasskeyInFlow|checkApprovalPasskeySpendingFlow|approvalPasskeyOfferInFlow|flowPasskeyCovers)\(/g) ?? []).length;
        if (count > 0) readers[file] = count;
      }
      expect(Object.keys(readers).sort()).toEqual([
        'routes/delegate.ts', 'routes/keys.ts', 'routes/native-delegation-consent.ts', 'services/approval-passkey.ts',
      ].sort());
      // delegate: authorize-sign-preview offer and authorize-sign check. keys: the exact-byte offer and signature.
      expect(readers['routes/delegate.ts']).toBe(2);
      expect(readers['routes/keys.ts']).toBe(2);
    });
  });

  describe('the flow header is for OpenKey\'s own pages', () => {
    test('an app origin cannot send it with a session, and an untrusted origin is not allowed to read the API', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await iframeSignIn(passkey, id);
      // The embedding app's origin: the bearer and the delegate routes refuse it before any handler reads the header.
      const fromApp = await app.fetch(new Request(`${api}/api/delegate/authorize-sign-release`, {
        method: 'POST', headers: { origin: embedder, 'content-type': 'application/json', ...signedIn.auth, ...flow(id) }, body: '{}',
      }));
      expect(fromApp.status).toBe(403);
      const keysFromApp = await app.fetch(new Request(`${api}/api/keys/${owner.keyId}/sign/passkey`, {
        method: 'POST', headers: { origin: embedder, 'content-type': 'application/json', ...signedIn.auth, ...flow(id) }, body: '{"message":"hello"}',
      }));
      expect(keysFromApp.status).toBe(403);
      expect(await flowRows(owner.userId)).toBe(1);

      for (const [origin, allowed] of [[web, true], [embedder, false]] as const) {
        const preflight = await app.fetch(new Request(`${api}/api/delegate/authorize-sign-preview`, {
          method: 'OPTIONS',
          headers: { origin, 'access-control-request-method': 'POST', 'access-control-request-headers': `content-type,${FLOW_HEADER}` },
        }));
        expect(preflight.headers.get('access-control-allow-origin') === origin, origin).toBe(allowed);
        // Without Access-Control-Allow-Origin the browser blocks the preflight, whatever the other headers say.
        if (!allowed) expect(preflight.headers.get('access-control-allow-origin')).toBeNull();
      }
    });
  });
}
