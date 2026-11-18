// TC-3232: declining the Terms stops the account's renewals at the node, then signs out, through the whole API
// (routes, Better Auth, managed-key signing) on PGlite. Two kinds of lease are stopped: the ones OpenKey recorded
// (approval links) and the sign-in leases it never recorded, which are found by listing the owner's active grants
// at the node. The node is a loopback stand-in; it records what it was asked to revoke. Runs in a child process.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';
import { mockModules } from './mock-module';

const root = resolve(import.meta.dir, '../../../..');
const ORIGIN = 'https://openkey.test';
const API = 'https://api.openkey.test';

if (process.env.OPENKEY_TERMS_DECLINE_TEST_CHILD !== '1') {
  test('declining the Terms stops renewals and signs out', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_TERMS_DECLINE_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: API,
        BETTER_AUTH_SECRET: 'terms-decline-isolated-test-secret',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: ORIGIN,
        CORS_ORIGIN: ORIGIN,
        TINYCLOUD_BOOTSTRAP_HOST: '',
        RESEND_API_KEY: '',
        GOOGLE_CLIENT_ID: '',
        GOOGLE_CLIENT_SECRET: '',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(exitCode, stdout + stderr).toBe(0);
  }, 300_000);
} else {
  const VERSION = '2026-12-01';
  const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const RENEWER_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
  const OTHER_RENEWER_DID = 'did:key:z6MkgWpiYdQV8pAr3dtHLdQsoZR3wF5wsS7fpkzAuX6q1PZj';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookieName: string;
  let secret: string;

  const releaseFile: Record<string, unknown> = {};
  function release(version: string | null) {
    Object.assign(releaseFile, { version, requiredVersion: null, textSha256: version ? 'a'.repeat(64) : null, whatChanged: null, privacyChanged: false });
  }
  release(null);
  await mockModules({ '../terms-release.json': () => ({ default: releaseFile }) });

  // The stand-in node. `listing` is what `POST /delegation/query` lists (in pages of the asked limit; from page
  // `failPage` on it answers 503); `revoked` the lease CIDs it was asked to revoke, read from the owner's signed
  // revocation; `queries` each listing's body.
  type Item = Record<string, unknown>;
  const node = {
    server: undefined as Server | undefined, origin: '', up: true, delayMs: 0, failPage: Infinity, refuseRevoke: false,
    listing: [] as Item[], revoked: [] as string[], queries: [] as Array<Record<string, unknown>>, activations: 0,
  };

  beforeAll(async () => {
    node.server = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(chunk as Buffer);
      const body = Buffer.concat(chunks).toString('utf8');
      if (node.delayMs) await delay(node.delayMs);
      if (response.destroyed) return;
      const reply = (status: number, value: unknown) => {
        response.writeHead(status, { 'content-type': 'application/json' });
        response.end(JSON.stringify(value));
      };
      if (!node.up) return reply(503, { error: 'down' });
      if (request.method === 'GET' && request.url === '/info') return reply(200, { nodeId: NODE_DID, features: [] });
      if (request.method === 'GET' && request.url === '/.well-known/tinycloud/node-keys') {
        return reply(200, { nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik', renewerEpoch: 0 });
      }
      const authorization = request.headers.authorization;
      if (request.method !== 'POST' || typeof authorization !== 'string') return reply(404, {});
      if (request.url === '/delegate') { node.activations++; return reply(200, {}); }
      if (request.url === '/delegation/query') {
        const query = JSON.parse(body) as { limit?: number; cursor?: string };
        node.queries.push(query);
        const start = query.cursor ? Number(query.cursor) : 0;
        const limit = query.limit ?? 100;
        if (start / limit >= node.failPage) return reply(503, { error: 'busy' });
        const items = node.listing.slice(start, start + limit);
        const next = start + limit < node.listing.length ? String(start + limit) : undefined;
        return reply(200, { schemaVersion: 2, items, ...(next ? { nextCursor: next } : {}) });
      }
      if (request.url === '/revoke') {
        if (node.refuseRevoke) return reply(503, { error: 'busy' });
        // The signed revocation is CBOR; its audience `ucan:<lease CID>` is a text string after its one-byte length.
        const signed = Buffer.from(authorization.replace(/^Bearer\s+/i, ''), 'base64url');
        const at = signed.indexOf('ucan:');
        const cid = at > 0 ? signed.subarray(at, at + signed[at - 1]!).toString('utf8').slice('ucan:'.length) : undefined;
        if (cid) node.revoked.push(cid);
        return reply(200, { revoked: true, cid });
      }
      return reply(404, {});
    });
    node.server.listen(0, '127.0.0.1');
    await once(node.server, 'listening');
    node.origin = `http://127.0.0.1:${(node.server.address() as { port: number }).port}`;
    process.env.TINYCLOUD_BOOTSTRAP_HOST = node.origin;

    directory = await mkdtemp(join(tmpdir(), 'openkey-terms-decline-'));
    const database = new PGlite(directory);
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    } finally { await database.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    // Loaded after DATABASE_URL is set: the API modules open their database when loaded.
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    cookieName = context.authCookies.sessionToken.name;
    secret = context.secret;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    node.server?.close();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  function resetNode() {
    Object.assign(node, { up: true, delayMs: 0, failPage: Infinity, refuseRevoke: false, listing: [], revoked: [], queries: [], activations: 0 });
  }

  async function account(keyType: 'MANAGED' | 'EXTERNAL' = 'MANAGED') {
    const { createTeeClient, seal } = await import('@openkey/tee');
    const { privateKeyToAccount } = await import('viem/accounts');
    const { createSealingContext } = await import('../services/key-sealing');
    const userId = `decline-${randomUUID()}`;
    const privateKey = `0x${randomBytes(32).toString('hex')}` as const;
    const wallet = privateKeyToAccount(privateKey);
    const sealingContext = createSealingContext();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.ethereumKey.create({ data: {
      userId, address: wallet.address, publicKey: wallet.address, keyIndex: 0, keyType, sealingContext: keyType === 'MANAGED' ? sealingContext : null,
      sealedBlob: keyType === 'MANAGED' ? await seal(privateKey, await createTeeClient().deriveKey(`openkey/key/${sealingContext}`)) : null,
    } });
    const session = async () => {
      const token = randomUUID();
      const id = randomUUID();
      await prisma.session.create({ data: { id, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
      return { id, token, cookie: (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]! };
    };
    return { userId, wallet, ownerDid: `did:pkh:eip155:1:${wallet.address}`, session };
  }

  // CIDv1 base32, the length of a real one (59 characters); the kind and a counter keep them apart.
  let cids = 0;
  const cid = (kind: string) => `bafkr4i${kind}${(cids++).toString().replace(/\d/g, (d) => 'abcdefghij'[Number(d)]!)}`.padEnd(59, 'a');

  /** A lease OpenKey recorded when an approval link was approved, admitted at the stand-in node. */
  async function recordedLease(owner: Awaited<ReturnType<typeof account>>, sessionId: string | null) {
    const leaseCid = cid('recorded');
    await prisma.renewalLease.create({ data: {
      leaseCid, userId: owner.userId, sessionId, approvalRequestId: null, ownerDid: owner.ownerDid,
      originalCid: cid('original'), nodeOrigin: node.origin, nodeDid: NODE_DID, renewerDid: RENEWER_DID,
      leaseLifetimeSeconds: 3600, approvedAt: new Date(), leaseExpiresAt: new Date(Date.now() + 3_600_000), grantSiwe: 'the approved grant',
      admittedAt: new Date(),
    } });
    return leaseCid;
  }

  /** One row of the node's account listing: a delegation the owner granted. */
  function granted(owner: { ownerDid: string }, delegateDid: string, resources: Array<{ resource: string; actions: string[] }>, extra: Item = {}): Item {
    const now = Date.now();
    return {
      cid: cid('listed'), direction: 'granted', delegatorDid: owner.ownerDid, delegateDid,
      resources: resources.map((entry) => ({ ...entry, caveats: entry.actions.map(() => ({})) })), parents: [],
      issuedAt: new Date(now).toISOString(), notBefore: null, expiresAt: new Date(now + 3_600_000).toISOString(), status: 'active', ...extra,
    };
  }
  const signInLease = (owner: { ownerDid: string }, delegateDid = RENEWER_DID) =>
    granted(owner, delegateDid, [{ resource: `urn:cid:${cid('grant')}`, actions: ['tinycloud.delegation/renew'] }]);

  const decline = (cookie: string, headers: Record<string, string> = {}) => app.fetch(new Request(`${API}/api/account/terms/decline`, {
    method: 'POST', headers: { cookie, origin: ORIGIN, ...headers },
  }));
  const revokedAt = async (leaseCid: string) => (await prisma.renewalLease.findUnique({ where: { leaseCid } }))?.revokedAt ?? null;
  const sessionExists = async (id: string) => (await prisma.session.count({ where: { id } })) === 1;
  const scope = () => ({ node: node.origin, chainIds: [1] });

  describe('declining the Terms', () => {
    test('stops every lease the account recorded, under any session, then signs this session out', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      const here = await owner.session();
      const elsewhere = await owner.session();
      const mine = await recordedLease(owner, here.id);
      const other = await recordedLease(owner, elsewhere.id);
      const unbound = await recordedLease(owner, null);

      const response = await decline(here.cookie);
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await response.json()).toEqual({ signedOut: true, renewals: { stopped: 3, notStopped: 0, walletRequired: 0, nodeChecked: true, nodeScope: scope() } });
      for (const leaseCid of [mine, other, unbound]) expect(await revokedAt(leaseCid)).not.toBeNull();
      expect([...node.revoked].sort()).toEqual([mine, other, unbound].sort());
      // Only this session ends; the cookie is cleared.
      expect(await sessionExists(here.id)).toBe(false);
      expect(await sessionExists(elsewhere.id)).toBe(true);
      expect(response.headers.getSetCookie().some((cookie) => cookie.startsWith(`${cookieName}=;`) || /Max-Age=0/i.test(cookie))).toBe(true);
    });

    test('stops the sign-in leases OpenKey never recorded, found at the node, and nothing else the owner granted', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      const here = await owner.session();
      const recorded = await recordedLease(owner, here.id);
      const leases = [signInLease(owner), signInLease(owner)];
      const recordedListed = { ...signInLease(owner), cid: recorded };
      const keep = [
        signInLease(owner, OTHER_RENEWER_DID),
        granted(owner, 'did:key:z6MkApp', [{ resource: `tinycloud:pkh:eip155:1:${owner.wallet.address}:default/kv/notes/`, actions: ['tinycloud.kv/get'] }]),
        granted(owner, RENEWER_DID, [{ resource: `urn:cid:${cid('grant')}`, actions: ['tinycloud.delegation/renew', 'tinycloud.delegation/revoke'] }]),
        granted(owner, RENEWER_DID, [
          { resource: `urn:cid:${cid('grant')}`, actions: ['tinycloud.delegation/renew'] },
          { resource: `urn:cid:${cid('grant')}`, actions: ['tinycloud.delegation/renew'] },
        ]),
        { ...signInLease(owner), delegatorDid: 'did:pkh:eip155:1:0x00000000000000000000000000000000000000aa' },
      ];
      // More than one page: every page is read.
      const filler = Array.from({ length: 120 }, () => granted(owner, 'did:key:z6MkApp', [{ resource: `tinycloud:pkh:eip155:1:${owner.wallet.address}:default/kv/x/`, actions: ['tinycloud.kv/get'] }]));
      node.listing = [...filler, leases[0]!, ...keep, recordedListed, leases[1]!];

      const response = await decline(here.cookie);
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await response.json()).toEqual({ signedOut: true, renewals: { stopped: 3, notStopped: 0, walletRequired: 0, nodeChecked: true, nodeScope: scope() } });
      // The recorded lease once, by its record; the two sign-in leases by their listing; nothing else.
      expect([...node.revoked].sort()).toEqual([recorded, leases[0]!.cid as string, leases[1]!.cid as string].sort());
      expect(await revokedAt(recorded)).not.toBeNull();
      expect(node.queries.length).toBeGreaterThan(1);
      for (const query of node.queries) expect(query).toMatchObject({ direction: 'granted', status: 'active' });
      expect(await sessionExists(here.id)).toBe(false);
    });

    test('a lease the node lists with a CID that is not one is never signed for, and is reported not stopped', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      const lease = signInLease(owner);
      const evil = cid('evil');
      const newline = `${evil}\nResources:\n- tinycloud:pkh:eip155:1:${owner.wallet.address}:default/kv/`;
      node.listing = [{ ...signInLease(owner), cid: newline }, { ...signInLease(owner), cid: 'bafy-lease' }, lease];
      const { stopRenewalsOnDecline, defaultDeclineDeps } = await import('../services/terms-decline');
      const signed: string[] = [];
      const report = await stopRenewalsOnDecline(prisma, owner.userId, {
        ...defaultDeclineDeps,
        signManaged: async (key, sealedBlob, message) => { signed.push(message); return defaultDeclineDeps.signManaged(key, sealedBlob, message); },
        afterAdmissionWindow: () => {},
      });
      expect(report).toEqual({ stopped: 1, notStopped: 2, walletRequired: 0, nodeChecked: true, nodeScope: scope() });
      expect(node.revoked).toEqual([lease.cid as string]);
      // The listing session and the one revocation; neither carries the listed text.
      expect(signed).toHaveLength(2);
      for (const message of signed) {
        expect(message).not.toContain(evil);
        expect(message).not.toContain('default/kv/');
        expect(message).not.toContain('bafy-lease');
      }
    });

    test('an account signed with an outside wallet is reported, not signed for, and still signed out', async () => {
      resetNode();
      release(VERSION);
      const owner = await account('EXTERNAL');
      const here = await owner.session();
      const recorded = await recordedLease(owner, here.id);
      node.listing = [signInLease(owner)];

      const response = await decline(here.cookie);
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await response.json()).toEqual({ signedOut: true, renewals: { stopped: 0, notStopped: 0, walletRequired: 1, nodeChecked: false, nodeScope: null } });
      expect(node.revoked).toEqual([]);
      expect(node.queries).toEqual([]);
      expect(await revokedAt(recorded)).toBeNull();
      expect(await sessionExists(here.id)).toBe(false);
    });

    test('a node list that fails part way still stops the leases found before it failed, and says the list is incomplete', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      const here = await owner.session();
      const first = signInLease(owner);
      const later = signInLease(owner);
      const filler = Array.from({ length: 100 }, () => granted(owner, 'did:key:z6MkApp', [{ resource: `tinycloud:pkh:eip155:1:${owner.wallet.address}:default/kv/x/`, actions: ['tinycloud.kv/get'] }]));
      node.listing = [first, ...filler, later];
      node.failPage = 1;

      const response = await decline(here.cookie);
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await response.json()).toEqual({ signedOut: true, renewals: { stopped: 1, notStopped: 0, walletRequired: 0, nodeChecked: false, nodeScope: scope() } });
      expect(node.revoked).toEqual([first.cid as string]);
    });

    test('a sign-in lease the app admits just after the node was listed is stopped by the second pass', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      const { stopRenewalsOnDecline, defaultDeclineDeps } = await import('../services/terms-decline');
      let secondPass: (() => Promise<void>) | undefined;
      const report = await stopRenewalsOnDecline(prisma, owner.userId, { ...defaultDeclineDeps, afterAdmissionWindow: (pass) => { secondPass = pass; } });
      expect(report).toEqual({ stopped: 0, notStopped: 0, walletRequired: 0, nodeChecked: true, nodeScope: scope() });

      const admittedLate = signInLease(owner);
      node.listing = [admittedLate];
      await secondPass!();
      expect(node.revoked).toEqual([admittedLate.cid as string]);
    });

    test('a sign-in lease recorded but settled as never admitted, which its app admitted later, is stopped by its listing', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      const { stopRenewalsOnDecline, defaultDeclineDeps } = await import('../services/terms-decline');
      const deps = { ...defaultDeclineDeps, afterAdmissionWindow: () => undefined };
      // A stop found nothing at the node more than ten minutes after signing; the app admitted the lease after that.
      const settled = async () => {
        const leaseCid = cid('settled');
        await prisma.renewalLease.create({ data: {
          leaseCid, userId: owner.userId, sessionId: null, approvalRequestId: null, ownerDid: owner.ownerDid,
          originalCid: cid('original'), nodeOrigin: node.origin, nodeDid: NODE_DID, renewerDid: RENEWER_DID,
          leaseLifetimeSeconds: 3600, approvedAt: new Date(Date.now() - 20 * 60_000), leaseExpiresAt: new Date(Date.now() + 3_600_000),
          grantSiwe: 'the signed-in grant', neverAdmittedAt: new Date(Date.now() - 5 * 60_000),
        } });
        return leaseCid;
      };

      const refused = await settled();
      node.listing = [{ ...signInLease(owner), cid: refused }];
      node.refuseRevoke = true;
      // Not stopped while the node refuses: the report says so, and never counts it stopped.
      expect(await stopRenewalsOnDecline(prisma, owner.userId, deps)).toEqual({ stopped: 0, notStopped: 1, walletRequired: 0, nodeChecked: true, nodeScope: scope() });

      node.refuseRevoke = false;
      node.revoked = [];
      const report = await stopRenewalsOnDecline(prisma, owner.userId, deps);
      expect(node.revoked).toEqual([refused]);
      expect(report).toEqual({ stopped: 1, notStopped: 0, walletRequired: 0, nodeChecked: true, nodeScope: scope() });
    });

    test('the second pass leaves alone a lease signed after the person accepted a version', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      const { stopRenewalsOnDecline, defaultDeclineDeps } = await import('../services/terms-decline');
      let secondPass: (() => Promise<void>) | undefined;
      await stopRenewalsOnDecline(prisma, owner.userId, { ...defaultDeclineDeps, afterAdmissionWindow: (pass) => { secondPass = pass; } });

      expect((await app.fetch(new Request(`${API}/api/account/terms/accept`, {
        method: 'POST', headers: { cookie: (await owner.session()).cookie, origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify({ version: VERSION }),
      }))).status).toBe(200);
      node.listing = [signInLease(owner)];
      await secondPass!();
      expect(node.revoked).toEqual([]);
    });

    test('after a decline the account gets no new lease signed: every route that signs one waits for acceptance', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      expect((await decline((await owner.session()).cookie)).status).toBe(200);
      const again = await owner.session();
      // An approval with renewal (`/`, `/complete`), an app sign-in (`/authorize-sign`) and the signer (`/sign`,
      // which has its own auth) all sit behind the gate.
      for (const path of ['/api/delegate/', '/api/delegate/complete', '/api/delegate/authorize-sign', '/api/delegate/sign']) {
        const response = await app.fetch(new Request(`${API}${path}`, {
          method: 'POST', headers: { cookie: again.cookie, origin: ORIGIN, 'content-type': 'application/json' }, body: '{}',
        }));
        expect(response.status, path).toBe(403);
        expect(await response.json(), path).toMatchObject({ error: 'terms_required' });
      }
    });

    test('is refused with a session token, once accepted, and with no Terms version set; nothing is stopped', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      const here = await owner.session();
      const recorded = await recordedLease(owner, here.id);
      node.listing = [signInLease(owner)];

      const bearer = await app.fetch(new Request(`${API}/api/account/terms/decline`, {
        method: 'POST', headers: { authorization: `Bearer ${here.token}`, origin: ORIGIN },
      }));
      expect(bearer.status).toBe(403);

      expect((await app.fetch(new Request(`${API}/api/account/terms/accept`, {
        method: 'POST', headers: { cookie: here.cookie, origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify({ version: VERSION }),
      }))).status).toBe(200);
      const accepted = await decline(here.cookie);
      expect(accepted.status).toBe(409);
      expect(await accepted.json()).toEqual({ error: 'terms_not_required' });

      release(null);
      const other = await account();
      const otherSession = await other.session();
      const noRelease = await decline(otherSession.cookie);
      expect(noRelease.status).toBe(409);

      expect(node.revoked).toEqual([]);
      expect(await revokedAt(recorded)).toBeNull();
      expect(await sessionExists(here.id)).toBe(true);
      expect(await sessionExists(otherSession.id)).toBe(true);
    });

    test('a node that is down or slow never keeps the person signed in', async () => {
      resetNode();
      release(VERSION);
      const owner = await account();
      const down = await owner.session();
      const recorded = await recordedLease(owner, down.id);
      node.up = false;
      const refused = await decline(down.cookie);
      expect(refused.status, await refused.clone().text()).toBe(200);
      expect(await refused.json()).toEqual({ signedOut: true, renewals: { stopped: 0, notStopped: 1, walletRequired: 0, nodeChecked: false, nodeScope: null } });
      expect(await revokedAt(recorded)).toBeNull();
      expect(await sessionExists(down.id)).toBe(false);

      // A node that answers too late: the answer comes within the budgets (3 s for the decline's stop, up to 3 s more
      // for sign-out's own) and the session still ends.
      node.up = true;
      node.delayMs = 8_000;
      const slow = await owner.session();
      const started = Date.now();
      const late = await decline(slow.cookie);
      expect(late.status).toBe(200);
      expect(Date.now() - started).toBeLessThan(7_000);
      expect(await late.json()).toMatchObject({ signedOut: true, renewals: { nodeChecked: false } });
      expect(await sessionExists(slow.id)).toBe(false);
      node.delayMs = 0;
    }, 30_000);
  });
}
