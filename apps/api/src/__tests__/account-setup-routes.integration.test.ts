// The account setup page's routes against the real API on PGlite with the tracked migrations: one approval per
// request, bound to the user, the session and the stored record text, then the setup and the location record. Runs in
// a child process: the API reads its relying party, origins and database when loaded. The node and the registry are
// in-process fakes; no request leaves the process.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
import { createSoftPasskey, type SoftPasskey } from './soft-passkey';

const root = resolve(import.meta.dir, '../../../..');
const web = 'https://openkey.test';
const node = 'https://node.tinycloud.xyz';

if (process.env.OPENKEY_ACCOUNT_SETUP_ROUTES_CHILD !== '1') {
  test('the account setup routes approve one stored record once, for its own session', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_ACCOUNT_SETUP_ROUTES_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: web,
        CORS_ORIGIN: web,
        TINYCLOUD_BOOTSTRAP_HOST: node,
        TINYCLOUD_BOOTSTRAP_ON_SIGN: '',
        TINYCLOUD_BOOTSTRAP_SWEEP: 'off',
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
  const nodeDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const SPACES = ['default', 'applications', 'account', 'secrets', 'public', 'agents'];
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let tee: typeof import('@openkey/tee');
  let sdk: typeof import('@tinycloud/sdk-core');
  let stepUp: typeof import('../services/account-setup-step-up');
  let codes: typeof import('../services/email-code-storage');
  let bootstrap: typeof import('../services/tinycloud-bootstrap');
  let registryUrl: string;

  const originalFetch = globalThis.fetch;
  /** The fake registry: owner key → the record it holds. */
  const records = new Map<string, Record<string, unknown>>();
  const puts: Record<string, unknown>[] = [];
  let bootstrapRuns = 0;

  function fakeFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = String(input instanceof Request ? input.url : input);
    if (url === `${node}/info`) return Promise.resolve(Response.json({ nodeId: nodeDid }));
    if (url === `${node}/.well-known/tinycloud/node-keys`) return Promise.resolve(Response.json({ nodeDid }));
    if (url.startsWith(`${registryUrl}/v2/locations/`)) {
      const key = decodeURIComponent(url.slice(`${registryUrl}/v2/locations/`.length));
      if ((init?.method ?? 'GET') === 'PUT') {
        const record = JSON.parse(String(init!.body)) as Record<string, unknown>;
        puts.push(record);
        records.set(key, record);
        return Promise.resolve(Response.json({ record, status: 'created' }, { status: 201 }));
      }
      const record = records.get(key);
      return Promise.resolve(record
        ? Response.json({ record })
        : Response.json({ error: 'location record not found' }, { status: 404 }));
    }
    return Promise.reject(new Error(`External network disabled in this test: ${url}`));
  }

  beforeAll(async () => {
    globalThis.fetch = fakeFetch as typeof fetch;
    directory = await mkdtemp(join(tmpdir(), 'openkey-account-setup-routes-'));
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
    sdk = await import('@tinycloud/sdk-core');
    registryUrl = sdk.DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL;
    stepUp = await import('../services/account-setup-step-up');
    codes = await import('../services/email-code-storage');
    bootstrap = await import('../services/tinycloud-bootstrap');
    bootstrap.setTinyCloudBootstrapProbeForTests(async () => {});
    bootstrap.setTinyCloudBootstrapExecutorForTests(async () => { bootstrapRuns += 1; });
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    secret = context.secret;
    cookieName = context.authCookies.sessionToken.name;
  }, 120_000);

  afterAll(async () => {
    globalThis.fetch = originalFetch;
    bootstrap?.setTinyCloudBootstrapProbeForTests();
    bootstrap?.setTinyCloudBootstrapExecutorForTests();
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  beforeEach(() => {
    puts.length = 0;
    bootstrapRuns = 0;
  });

  type Account = { userId: string; sessionId: string; cookie: string; keyId: string; address: string; privateKey: `0x${string}` };

  async function session(userId: string): Promise<{ sessionId: string; cookie: string }> {
    const sessionId = randomUUID();
    const token = randomBytes(32).toString('base64url');
    await prisma.session.create({ data: { id: sessionId, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
    return { sessionId, cookie: (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]! };
  }

  async function account(options: { keyType?: 'MANAGED' | 'EXTERNAL'; emailVerified?: boolean } = {}): Promise<Account> {
    const userId = randomUUID();
    await prisma.user.create({ data: {
      id: userId, email: `${userId}@example.test`, name: userId, emailVerified: options.emailVerified ?? true,
    } });
    const { sessionId, cookie } = await session(userId);
    const privateKey = tee.generatePrivateKey();
    const address = tee.getAddressFromPrivateKey(privateKey);
    if (options.keyType === 'EXTERNAL') {
      const key = await prisma.ethereumKey.create({ data: { userId, address, publicKey: '0x1', keyType: 'EXTERNAL' } });
      return { userId, sessionId, cookie, keyId: key.id, address, privateKey };
    }
    const sealingContext = randomBytes(32).toString('base64url');
    const sealingKey = await tee.createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    const key = await prisma.ethereumKey.create({ data: {
      userId, address, publicKey: '0x1', sealedBlob: await tee.seal(privateKey, sealingKey), sealingContext,
      keyType: 'MANAGED', isCanonicalTinyCloud: true,
    } });
    return { userId, sessionId, cookie, keyId: key.id, address, privateKey };
  }

  const post = (path: string, headers: Record<string, string>, body: unknown = {}) => app.fetch(new Request(`${api}${path}`, {
    method: 'POST',
    headers: { origin: web, 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  }));

  async function json(response: Response, status: number): Promise<Record<string, any>> {
    expect(response.status, await response.clone().text()).toBe(status);
    return await response.json() as Record<string, any>;
  }

  async function prepare(owner: { cookie: string; keyId: string }, extra: Record<string, unknown> = {}) {
    return json(await post('/api/account-setup/prepare', { cookie: owner.cookie }, { keyId: owner.keyId, ...extra }), 200);
  }

  async function assertion(passkey: SoftPasskey, owner: { cookie: string }, id: string) {
    const offer = await json(await post(`/api/account-setup/${id}/passkey`, { cookie: owner.cookie }), 200);
    expect(offer.stepUp).toBe('passkey');
    return { challengeToken: offer.challengeToken as string, response: passkey.assert(offer.options as PublicKeyCredentialRequestOptionsJSON) };
  }

  /** Replaces the mailed code with a known one: the database holds only its keyed hash. */
  async function knownCode(sessionId: string, requestId: string, code: string) {
    const identifier = stepUp.accountSetupCodeIdentifier(sessionId, requestId);
    await prisma.verification.updateMany({ where: { identifier }, data: { value: `${codes.stepUpCodeDigest(identifier, code)}:0` } });
  }

  describe('who may ask', () => {
    test('a bearer token or another site is refused before anything is read', async () => {
      const owner = await account();
      const bearer = await post('/api/account-setup/prepare', { cookie: owner.cookie, authorization: 'Bearer x' }, { keyId: owner.keyId });
      expect(bearer.status).toBe(403);
      const foreign = await app.fetch(new Request(`${api}/api/account-setup/prepare`, {
        method: 'POST',
        headers: { origin: 'https://app.example', cookie: owner.cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ keyId: owner.keyId }),
      }));
      expect(foreign.status).toBe(403);
      expect(await prisma.accountSetupRequest.count({ where: { userId: owner.userId } })).toBe(0);
    });

    test('another user\'s key, an archived key and a wallet key get no row', async () => {
      const owner = await account();
      const other = await account();
      await json(await post('/api/account-setup/prepare', { cookie: owner.cookie }, { keyId: other.keyId }), 404);

      await prisma.ethereumKey.update({ where: { id: owner.keyId }, data: { archivedAt: new Date() } });
      await json(await post('/api/account-setup/prepare', { cookie: owner.cookie }, { keyId: owner.keyId }), 404);

      const wallet = await account({ keyType: 'EXTERNAL' });
      const refused = await json(await post('/api/account-setup/prepare', { cookie: wallet.cookie }, { keyId: wallet.keyId }), 403);
      expect(refused).toMatchObject({ code: 'ACCOUNT_SETUP_UNAVAILABLE', reason: 'wallet_key' });
      expect(await prisma.accountSetupRequest.count({ where: { userId: { in: [owner.userId, wallet.userId] } } })).toBe(0);
    });

    test('an account with a record is set up: no row, nothing to sign', async () => {
      const owner = await account();
      records.set(owner.address, { version: 2 });
      try {
        expect(await prepare(owner)).toEqual({ state: 'present' });
        expect(await prisma.accountSetupRequest.count({ where: { userId: owner.userId } })).toBe(0);
      } finally {
        records.delete(owner.address);
      }
    });

    test('an account that can confirm neither by passkey nor by email gets no row', async () => {
      const owner = await account({ emailVerified: false });
      const refused = await json(await post('/api/account-setup/prepare', { cookie: owner.cookie }, { keyId: owner.keyId }), 403);
      expect(refused).toMatchObject({ code: 'ACCOUNT_SETUP_UNAVAILABLE', reason: 'no_step_up' });
      expect(await prisma.accountSetupRequest.count({ where: { userId: owner.userId } })).toBe(0);
    });
  });

  describe('the record', () => {
    test('is the server\'s: chain 1, the six account spaces on the TinyCloud node, whatever the request says', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const prepared = await prepare(owner, {
        chainId: 5, nodeUrl: 'https://evil.example', subject: 'did:pkh:eip155:5:0x0', record: '{}', requestOrigin: 'https://app.example',
      });
      expect(prepared).toMatchObject({ state: 'ready', stepUp: 'passkey', nodeUrl: node });
      const row = await prisma.accountSetupRequest.findUniqueOrThrow({ where: { id: prepared.id } });
      expect(row).toMatchObject({ chainId: 1, nodeUrl: node, nodeDid, requestOrigin: 'https://app.example', placement: 'tinycloud' });
      expect(prepared.record).toBe(row.payload);

      const record = JSON.parse(row.payload);
      const owned = sdk.validateLocationRecordV2Payload(record);
      expect(owned.subject).toBe(`did:pkh:eip155:1:${owner.address}`);
      expect(owned.sequence).toBe(0);
      expect(owned.nodes).toEqual([{ did: nodeDid, url: node }]);
      expect(owned.encryptionNode).toBe(nodeDid);
      expect(owned.spaces.map((space) => space.space).sort()).toEqual(
        SPACES.map((name) => `tinycloud:pkh:eip155:1:${owner.address}:${name}`).sort(),
      );
      for (const space of owned.spaces) expect(space.nodes).toEqual([{ did: nodeDid, mode: 'read-write' }]);
    });

    test('the CHECK keeps a row on chain 1', async () => {
      const owner = await account();
      const inserted = await prisma.$executeRaw`
        INSERT INTO "account_setup_request" ("id", "userId", "sessionId", "keyId", "chainId", "placement", "nodeUrl", "nodeDid",
          "payload", "payloadDigest", "expiresAt", "createdAt")
        VALUES (${randomUUID()}, ${owner.userId}, ${owner.sessionId}, ${owner.keyId}, 5, 'tinycloud', ${node}, ${nodeDid},
          '{}', 'x', now(), now())`.then(() => 'inserted', (error: Error) => error.message);
      expect(inserted).toContain('account_setup_request_chain_check');
    });
  });

  describe('approval', () => {
    test('a passkey for this row approves it once: the account is set up and the stored record is published', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const prepared = await prepare(owner);
      const auth = { cookie: owner.cookie };

      // The challenge binds the row and its stored digest: a digest in the body changes nothing.
      const offer = await json(await post(`/api/account-setup/${prepared.id}/passkey`, auth, { requestDigest: 'x' }), 200);
      const first = { challengeToken: offer.challengeToken, response: passkey.assert(offer.options) };

      const done = await json(await post(`/api/account-setup/${prepared.id}/approve`, auth, { passkeyAssertion: first }), 200);
      expect(done).toEqual({ state: 'published' });
      expect(bootstrapRuns).toBe(1);
      const state = await prisma.tinyCloudBootstrapState.findFirstOrThrow({ where: { keyId: owner.keyId } });
      expect(state).toMatchObject({ status: 'complete', authority: 'account-setup', chainId: 1, tinycloudHost: node });

      expect(puts).toHaveLength(1);
      const { signature, ...published } = puts[0]!;
      expect(sdk.canonicalLocationPayloadV2(published as never)).toBe(prepared.record);
      expect(await sdk.verifyLocationRecordV2({ ...published, signature } as never)).toBe(true);

      // Single use: the same row, a fresh assertion, a second call.
      await json(await post(`/api/account-setup/${prepared.id}/passkey`, auth), 404);
      await json(await post(`/api/account-setup/${prepared.id}/approve`, auth, { passkeyAssertion: first }), 409);
      expect(await json(await post(`/api/account-setup/${prepared.id}/finish`, auth), 200)).toEqual({ state: 'published' });
      expect(puts).toHaveLength(1);
    });

    test('an assertion for one row does not approve another, and a failed step-up leaves the row open', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const auth = { cookie: owner.cookie };
      const first = await prepare(owner);
      const forFirst = await assertion(passkey, owner, first.id);
      // A second session's prepare supersedes the first row; the assertion bound to it cannot approve the new one.
      const other = { ...await session(owner.userId), keyId: owner.keyId };
      const second = await prepare(other);
      expect(second.id).not.toBe(first.id);
      expect((await prisma.accountSetupRequest.findUniqueOrThrow({ where: { id: first.id } })).supersededAt).not.toBeNull();
      const refused = await json(await post(`/api/account-setup/${second.id}/approve`, { cookie: other.cookie }, { passkeyAssertion: forFirst }), 403);
      expect(refused.code).toBe('passkey_approval_invalid');
      // The superseded row is gone for its own session too.
      await json(await post(`/api/account-setup/${first.id}/approve`, auth, { passkeyAssertion: forFirst }), 409);
      // The refusal freed the lease: the right assertion approves the open row.
      const right = await assertion(passkey, other, second.id);
      expect(await json(await post(`/api/account-setup/${second.id}/approve`, { cookie: other.cookie }, { passkeyAssertion: right }), 200))
        .toEqual({ state: 'published' });
      expect(puts).toHaveLength(1);
    });

    test('another session of the same user cannot see, confirm or approve the row', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const prepared = await prepare(owner);
      const other = await session(owner.userId);
      await json(await post(`/api/account-setup/${prepared.id}/passkey`, { cookie: other.cookie }), 404);
      await json(await post(`/api/account-setup/${prepared.id}/email-code`, { cookie: other.cookie }), 404);
      await json(await post(`/api/account-setup/${prepared.id}/approve`, { cookie: other.cookie }, { emailCode: '000000' }), 409);
      await json(await post(`/api/account-setup/${prepared.id}/finish`, { cookie: other.cookie }), 404);
    });

    test('an expired row cannot be confirmed or approved', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const prepared = await prepare(owner);
      const forRow = await assertion(passkey, owner, prepared.id);
      await prisma.accountSetupRequest.update({ where: { id: prepared.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
      await json(await post(`/api/account-setup/${prepared.id}/passkey`, { cookie: owner.cookie }), 404);
      await json(await post(`/api/account-setup/${prepared.id}/approve`, { cookie: owner.cookie }, { passkeyAssertion: forRow }), 409);
      expect(bootstrapRuns).toBe(0);
    });

    test('no assertion and no code is not an approval', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const prepared = await prepare(owner);
      const refused = await json(await post(`/api/account-setup/${prepared.id}/approve`, { cookie: owner.cookie }, {}), 403);
      expect(refused.code).toBe('passkey_approval_required');
      expect(bootstrapRuns).toBe(0);
    });
  });

  describe('email code', () => {
    test('is offered only without a step-up passkey, and an email code never stands in for a passkey', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const prepared = await prepare(owner);
      const refused = await json(await post(`/api/account-setup/${prepared.id}/email-code`, { cookie: owner.cookie }), 403);
      expect(refused.code).toBe('passkey_approval_required');
      const approve = await json(await post(`/api/account-setup/${prepared.id}/approve`, { cookie: owner.cookie }, { emailCode: '123456' }), 403);
      expect(approve.code).toBe('passkey_approval_required');
    });

    test('three wrong codes end the code; a right code approves once', async () => {
      const owner = await account();
      // A passkey that does not count for step-up leaves the email code.
      await createSoftPasskey(prisma, owner.userId, false, web);
      const auth = { cookie: owner.cookie };
      const prepared = await prepare(owner);
      expect(prepared.stepUp).toBe('email');
      expect(await json(await post(`/api/account-setup/${prepared.id}/passkey`, auth), 200)).toMatchObject({ stepUp: 'email' });

      expect(await json(await post(`/api/account-setup/${prepared.id}/email-code`, auth), 200)).toMatchObject({ sent: true });
      expect(await json(await post(`/api/account-setup/${prepared.id}/email-code`, auth), 200)).toMatchObject({ sent: false });
      await knownCode(owner.sessionId, prepared.id, '424242');
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const wrong = await json(await post(`/api/account-setup/${prepared.id}/approve`, auth, { emailCode: '000000' }), 403);
        expect(wrong.code).toBe('account_setup_code_invalid');
      }
      const ended = await json(await post(`/api/account-setup/${prepared.id}/approve`, auth, { emailCode: '424242' }), 403);
      expect(ended.code).toBe('account_setup_code_ended');

      await json(await post(`/api/account-setup/${prepared.id}/email-code`, auth), 200);
      await knownCode(owner.sessionId, prepared.id, '424242');
      expect(await json(await post(`/api/account-setup/${prepared.id}/approve`, auth, { emailCode: '424242' }), 200))
        .toEqual({ state: 'published' });
      await json(await post(`/api/account-setup/${prepared.id}/approve`, auth, { emailCode: '424242' }), 409);
    });

    test('parallel approvals with one right code: exactly one is taken', async () => {
      const owner = await account();
      const auth = { cookie: owner.cookie };
      const prepared = await prepare(owner);
      await json(await post(`/api/account-setup/${prepared.id}/email-code`, auth), 200);
      await knownCode(owner.sessionId, prepared.id, '135790');
      const answers = await Promise.all(Array.from({ length: 6 }, () =>
        post(`/api/account-setup/${prepared.id}/approve`, auth, { emailCode: '135790' })));
      expect(answers.filter((answer) => answer.status === 200)).toHaveLength(1);
      expect(answers.every((answer) => answer.status === 200 || answer.status === 409 || answer.status === 403)).toBe(true);
      expect(bootstrapRuns).toBe(1);
      expect(puts).toHaveLength(1);
    });
  });

  describe('an existing record', () => {
    test('a record another device publishes after the tap is not overwritten: the outcome is present', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const prepared = await prepare(owner);
      const wallet = tee.createWalletFromPrivateKey(owner.privateKey);
      const elsewhere = await sdk.signLocationRecordV2(
        { ...JSON.parse(prepared.record), updated_at: new Date(Date.now() - 60_000).toISOString() },
        { type: 'did:pkh', signMessage: (message) => wallet.signMessage({ message }) },
      );
      records.set(owner.address, elsewhere as unknown as Record<string, unknown>);
      try {
        const right = await assertion(passkey, owner, prepared.id);
        const answer = await post(`/api/account-setup/${prepared.id}/approve`, { cookie: owner.cookie }, { passkeyAssertion: right });
        expect(await json(answer, 200)).toEqual({ state: 'present' });
        expect(puts).toHaveLength(0);
        expect(records.get(owner.address)).toBe(elsewhere as unknown as Record<string, unknown>);
      } finally {
        records.delete(owner.address);
      }
    });
  });
}
