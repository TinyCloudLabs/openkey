// A web sign flow's passkey cover is spent atomically by the approval that passes on it: of several parallel approvals
// for one flow exactly one passes the gate, and the offers only read the cover. Real API on PGlite with the tracked
// migrations, in a child process: the API reads its relying party, origins and database when loaded.
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

if (process.env.OPENKEY_WEB_FLOW_PARALLEL_CHILD !== '1') {
  test('the cover of a web sign flow is spent by exactly one parallel approval', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_WEB_FLOW_PARALLEL_CHILD: '1',
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
    directory = await mkdtemp(join(tmpdir(), 'openkey-web-flow-parallel-'));
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
  const post = (path: string, auth: Record<string, string>, body: unknown, headers: Record<string, string> = {}) =>
    app.fetch(new Request(`${api}${path}`, {
      method: 'POST',
      headers: { origin: web, 'content-type': 'application/json', ...auth, ...headers },
      body: JSON.stringify(body),
    }));
  const flow = (id: string): Record<string, string> => ({ [FLOW_HEADER]: id });
  const flowRows = (userId: string) => prisma.verification.count({ where: { userId, identifier: { startsWith: 'openkey-flow-passkey:' } } });
  const cookieHeader = (response: Response) => response.headers.getSetCookie().map((cookie) => cookie.split(';')[0]).join('; ');

  /** The pop-up's passkey sign-in: Better Auth's passkey routes with the session cookie, naming the flow. */
  async function popupSignIn(passkey: SoftPasskey, id: string) {
    const asked = await app.fetch(new Request(`${api}/api/auth/passkey/generate-authenticate-options`, { headers: { origin: web } }));
    expect(asked.status, await asked.clone().text()).toBe(200);
    const options = await asked.json() as PublicKeyCredentialRequestOptionsJSON;
    const response = await app.fetch(new Request(`${api}/api/auth/passkey/verify-authentication`, {
      method: 'POST',
      headers: { origin: web, 'content-type': 'application/json', cookie: cookieHeader(asked), ...flow(id) },
      body: JSON.stringify({ response: passkey.assert(options) }),
    }));
    expect(response.status, await response.clone().text()).toBe(200);
    return { auth: { cookie: cookieHeader(response) } };
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

  async function previewOf(auth: Record<string, string>, context: { authorizationContextToken: string; allowedActionIds: string[] }, id: string) {
    const { authorizationContextToken, allowedActionIds } = context;
    const previewed = await post('/api/delegate/authorize-sign-preview', auth,
      { authorizationContextToken, selectedActionIds: allowedActionIds }, flow(id));
    expect(previewed.status, await previewed.clone().text()).toBe(200);
    const body = await previewed.json() as { previewApprovalToken: string; passkey: { required: boolean } };
    return {
      passkey: body.passkey,
      approval: { authorizationContextToken, previewApprovalToken: body.previewApprovalToken, selectedActionIds: allowedActionIds, protocolVersion: 1 },
    };
  }

  async function alwaysAsking() {
    const owner = await account();
    const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
    await prisma.user.update({ where: { id: owner.userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
    return { owner, passkey };
  }

  const statuses = (responses: Response[]) => responses.map((response) => response.status).sort();

  describe('parallel approvals for one flow', () => {
    test('authorize-sign: of two approvals with their own previews exactly one passes on the cover', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const first = await previewOf(signedIn.auth, await prepareContext(owner, signedIn.auth), id);
      const second = await previewOf(signedIn.auth, await prepareContext(owner, signedIn.auth), id);
      expect(first.passkey).toEqual({ required: false });
      expect(second.passkey).toEqual({ required: false });

      const responses = await Promise.all([first, second].map((preview) =>
        post('/api/delegate/authorize-sign', signedIn.auth, preview.approval, flow(id))));
      expect(statuses(responses)).toEqual([200, 403]);
      const refused = responses.find((response) => response.status === 403)!;
      expect(await refused.json()).toMatchObject({ code: 'passkey_approval_required' });
      expect(await flowRows(owner.userId)).toBe(0);
    });

    test('authorize-sign: many parallel approvals still pass exactly once', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const previews = [];
      for (let i = 0; i < 5; i++) previews.push(await previewOf(signedIn.auth, await prepareContext(owner, signedIn.auth), id));
      const responses = await Promise.all(previews.map((preview) =>
        post('/api/delegate/authorize-sign', signedIn.auth, preview.approval, flow(id))));
      expect(statuses(responses)).toEqual([200, 403, 403, 403, 403]);
    });

    test('keys/:id/sign: exactly one covered signing per flow, however many arrive together', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const path = `/api/keys/${owner.keyId}/sign`;
      const responses = await Promise.all(Array.from({ length: 6 }, () =>
        post(path, signedIn.auth, { message: 'hello', requestOrigin: web }, flow(id))));
      expect(statuses(responses)).toEqual([200, 403, 403, 403, 403, 403]);
      for (const refused of responses.filter((response) => response.status === 403)) {
        expect(await refused.json()).toMatchObject({ code: 'passkey_approval_required' });
      }
      expect(await flowRows(owner.userId)).toBe(0);
      // Afterwards the flow has no cover.
      const later = await post(path, signedIn.auth, { message: 'hello', requestOrigin: web }, flow(id));
      expect(later.status).toBe(403);
    });

    test('a parallel approval for another flow of the same session is not covered by this one', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const path = `/api/keys/${owner.keyId}/sign`;
      const responses = await Promise.all([
        post(path, signedIn.auth, { message: 'hello', requestOrigin: web }, flow(id)),
        post(path, signedIn.auth, { message: 'hello', requestOrigin: web }, flow(newFlowId())),
      ]);
      expect(responses.map((response) => response.status)).toEqual([200, 403]);
    });

    test('the offers read the cover and never spend it, however many are made', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      const context = await prepareContext(owner, signedIn.auth);
      for (let i = 0; i < 4; i++) expect((await previewOf(signedIn.auth, context, id)).passkey).toEqual({ required: false });
      const offers = await Promise.all(Array.from({ length: 4 }, () =>
        post(`/api/keys/${owner.keyId}/sign/passkey`, signedIn.auth, { message: 'hello', requestOrigin: web }, flow(id))));
      for (const offer of offers) expect(await offer.json()).toEqual({ required: false });
      expect(await flowRows(owner.userId)).toBe(1);
    });

    test('an expired cover is not spent and the approval needs its own passkey', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const signedIn = await popupSignIn(passkey, id);
      await prisma.verification.updateMany({
        where: { userId: owner.userId, identifier: { startsWith: 'openkey-flow-passkey:' } }, data: { expiresAt: new Date(Date.now() - 1000) },
      });
      const refused = await post(`/api/keys/${owner.keyId}/sign`, signedIn.auth, { message: 'hello', requestOrigin: web }, flow(id));
      expect(refused.status).toBe(403);
      expect(await refused.json()).toMatchObject({ code: 'passkey_approval_required' });
    });
  });

  describe('the check that spends the cover', () => {
    const binding = { purpose: 'test', requestDigest: 'digest' };

    test('of many callers started together exactly one is let through on the cover', async () => {
      const { checkApprovalPasskeySpendingFlow } = await import('../services/approval-passkey');
      const { owner } = await alwaysAsking();
      const id = newFlowId();
      const subject = { userId: owner.userId, sessionId: owner.sessionId };
      for (let round = 0; round < 5; round++) {
        await prisma.verification.create({ data: {
          id: randomUUID(), identifier: `openkey-flow-passkey:${owner.sessionId}:${id}`, userId: owner.userId,
          value: 'passkey', expiresAt: new Date(Date.now() + 60_000),
        } });
        const results = await Promise.all(Array.from({ length: 12 }, () =>
          checkApprovalPasskeySpendingFlow(prisma, subject, binding, 'standard', undefined, id)));
        expect(results.filter((result) => result.refusal === null)).toEqual([{ refusal: null, method: 'FLOW_PASSKEY' }]);
        expect(results.filter((result) => result.refusal !== null)).toHaveLength(11);
        expect(await flowRows(owner.userId)).toBe(0);
      }
    });

    test('the native check reads the cover and leaves it, so an approve that fails after the gate can be retried', async () => {
      const { checkApprovalPasskeyInFlow } = await import('../services/approval-passkey');
      const { owner } = await alwaysAsking();
      const id = randomBytes(24).toString('base64url');
      await prisma.verification.create({ data: {
        id: randomUUID(), identifier: `openkey-flow-passkey:${owner.sessionId}:${id}`, userId: owner.userId,
        value: 'passkey', expiresAt: new Date(Date.now() + 60_000),
      } });
      const subject = { userId: owner.userId, sessionId: owner.sessionId };
      expect(await checkApprovalPasskeyInFlow(prisma, subject, binding, 'standard', undefined, id)).toEqual({ refusal: null, method: 'FLOW_PASSKEY' });
      expect(await checkApprovalPasskeyInFlow(prisma, subject, binding, 'standard', undefined, id)).toEqual({ refusal: null, method: 'FLOW_PASSKEY' });
      expect(await flowRows(owner.userId)).toBe(1);
    });

    test('another session, an expired cover and no flow id are not let through', async () => {
      const { checkApprovalPasskeySpendingFlow } = await import('../services/approval-passkey');
      const { owner } = await alwaysAsking();
      const id = newFlowId();
      await prisma.verification.create({ data: {
        id: randomUUID(), identifier: `openkey-flow-passkey:${owner.sessionId}:${id}`, userId: owner.userId,
        value: 'passkey', expiresAt: new Date(Date.now() + 60_000),
      } });
      const attempts = [
        { subject: { userId: owner.userId, sessionId: randomUUID() }, flowId: id },
        { subject: { userId: owner.userId, sessionId: null }, flowId: id },
        { subject: { userId: owner.userId, sessionId: owner.sessionId }, flowId: null },
        { subject: { userId: owner.userId, sessionId: owner.sessionId }, flowId: newFlowId() },
      ];
      for (const { subject, flowId } of attempts) {
        const result = await checkApprovalPasskeySpendingFlow(prisma, subject, binding, 'standard', undefined, flowId);
        expect(result.refusal).toMatchObject({ code: 'passkey_approval_required' });
      }
      expect(await flowRows(owner.userId)).toBe(1);
      // Expired: nothing is spent and nothing is let through.
      const later = new Date(Date.now() + 10 * 60_000);
      const expired = await checkApprovalPasskeySpendingFlow(
        prisma, { userId: owner.userId, sessionId: owner.sessionId }, binding, 'standard', undefined, id, undefined, later,
      );
      expect(expired.refusal).toMatchObject({ code: 'passkey_approval_required' });
      expect(await flowRows(owner.userId)).toBe(1);
    });
  });
}
