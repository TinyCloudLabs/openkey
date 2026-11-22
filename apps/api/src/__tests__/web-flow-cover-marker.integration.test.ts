// An offer for a web sign flow carries `flowCover: true` only when that flow's passkey cover is what waives the
// passkey, so the sign page can hold the cover to its visibility check. Real API on PGlite with the tracked
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

if (process.env.OPENKEY_WEB_FLOW_MARKER_CHILD !== '1') {
  test('an offer names the cover only when the cover waives it', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_WEB_FLOW_MARKER_CHILD: '1',
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
    directory = await mkdtemp(join(tmpdir(), 'openkey-web-flow-marker-'));
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
  const cookieHeader = (response: Response) => response.headers.getSetCookie().map((cookie) => cookie.split(';')[0]).join('; ');

  /** The sign page's passkey sign-in: Better Auth's passkey routes with the session cookie, naming the flow. */
  async function signIn(passkey: SoftPasskey, id: string) {
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

  type Offer = { required: boolean; flowCover?: unknown };

  async function previewOffer(auth: Record<string, string>, context: { authorizationContextToken: string; allowedActionIds: string[] }, headers: Record<string, string>) {
    const previewed = await post('/api/delegate/authorize-sign-preview', auth,
      { authorizationContextToken: context.authorizationContextToken, selectedActionIds: context.allowedActionIds }, headers);
    expect(previewed.status, await previewed.clone().text()).toBe(200);
    return (await previewed.json() as { passkey: Offer }).passkey;
  }

  async function exactOffer(owner: Account, auth: Record<string, string>, headers: Record<string, string>) {
    const offered = await post(`/api/keys/${owner.keyId}/sign/passkey`, auth, { message: 'hello', requestOrigin: web }, headers);
    expect(offered.status, await offered.clone().text()).toBe(200);
    return await offered.json() as Offer;
  }

  async function alwaysAsking() {
    const owner = await account();
    const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
    await prisma.user.update({ where: { id: owner.userId }, data: { passkeyApprovalMode: 'ALWAYS' } });
    return { owner, passkey };
  }

  describe('flowCover on an offer', () => {
    test('a cover that waives the offer marks it, on the preview and on the exact-byte offer', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const { auth } = await signIn(passkey, id);
      const context = await prepareContext(owner, auth);
      expect(await previewOffer(auth, context, flow(id))).toEqual({ required: false, flowCover: true });
      expect(await exactOffer(owner, auth, flow(id))).toEqual({ required: false, flowCover: true });
    });

    test('an offer without the flow header asks for the passkey and carries no marker', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const { auth } = await signIn(passkey, id);
      const context = await prepareContext(owner, auth);
      for (const offer of [await previewOffer(auth, context, {}), await exactOffer(owner, auth, {})]) {
        expect(offer.required).toBe(true);
        expect('flowCover' in offer).toBe(false);
      }
    });

    test('another flow id, a native-shaped id and a malformed id are not the cover and carry no marker', async () => {
      const { owner, passkey } = await alwaysAsking();
      const { auth } = await signIn(passkey, newFlowId());
      const context = await prepareContext(owner, auth);
      for (const headers of [flow(newFlowId()), flow(randomBytes(24).toString('base64url')), flow('w.short'), flow(`w.${'a'.repeat(33)}`)]) {
        for (const offer of [await previewOffer(auth, context, headers), await exactOffer(owner, auth, headers)]) {
          expect(offer.required).toBe(true);
          expect('flowCover' in offer).toBe(false);
        }
      }
    });

    test('another session does not see the cover, so no marker', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      await signIn(passkey, id);
      const other = await signIn(passkey, newFlowId());
      const context = await prepareContext(owner, other.auth);
      const offer = await previewOffer(other.auth, context, flow(id));
      expect(offer.required).toBe(true);
      expect('flowCover' in offer).toBe(false);
    });

    test('an expired cover asks for the passkey and carries no marker', async () => {
      const { owner, passkey } = await alwaysAsking();
      const id = newFlowId();
      const { auth } = await signIn(passkey, id);
      const context = await prepareContext(owner, auth);
      await prisma.verification.updateMany({
        where: { userId: owner.userId, identifier: { startsWith: 'openkey-flow-passkey:' } }, data: { expiresAt: new Date(Date.now() - 1_000) },
      });
      for (const offer of [await previewOffer(auth, context, flow(id)), await exactOffer(owner, auth, flow(id))]) {
        expect(offer.required).toBe(true);
        expect('flowCover' in offer).toBe(false);
      }
    });

    test('an account whose setting asks for no passkey gets an offer that needs none and carries no marker', async () => {
      const owner = await account();
      const auth = { cookie: owner.cookie };
      const context = await prepareContext(owner, auth);
      const id = newFlowId();
      for (const offer of [await previewOffer(auth, context, flow(id)), await exactOffer(owner, auth, flow(id)), await previewOffer(auth, context, {})]) {
        expect(offer).toEqual({ required: false });
      }
    });

    test('an email sign-in records no cover, so the offer asks and carries no marker', async () => {
      const { owner } = await alwaysAsking();
      const auth = { cookie: owner.cookie };
      const context = await prepareContext(owner, auth);
      const offer = await previewOffer(auth, context, flow(newFlowId()));
      expect(offer.required).toBe(true);
      expect('flowCover' in offer).toBe(false);
    });
  });
}
