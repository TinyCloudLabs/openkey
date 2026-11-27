// The reviewer account's own deletion writes an account-deletion event in its transaction, like an ordinary
// deletion, and a refused reviewer deletion writes none. Runs on PGlite.
import './tc1777-test-env';
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
if (!process.env.OPENKEY_REVIEWER_DELETE_EVENT_CHILD) {
  test('reviewer deletion writes an account-deletion event', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], { cwd: root, env: {
      ...process.env, OPENKEY_REVIEWER_DELETE_EVENT_CHILD: '1', APPLE_REVIEW_ENABLED: 'true', NODE_ENV: 'test', TEE_MODE: 'development',
      BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'reviewer-delete-event-test-secret-0123456789',
      WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
      ADMIN_API_KEY: 'isolated-reviewer-delete-event-admin', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
    }, stdout: 'pipe', stderr: 'pipe' });
    const [stdout, stderr, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(status, stdout + stderr).toBe(0);
  }, 120_000);
} else {
  const clientId = 'ok_e1d13d0b220379f37a553aa0391d28a4';
  const host = 'https://tee.node.tinycloud.xyz';
  const redirect = 'xyz.tinycloud.exo://openkey/callback';
  const api = 'https://api.openkey.test';
  const email = 'appreview@tinycloud.xyz';
  const code = randomBytes(32).toString('base64url');
  const appId = 'xyz.tinycloud.tinychat';
  const ceiling = { version: 1, appId, tinycloudHost: host,
    kv: { paths: [`${appId}/threads/`, `${appId}/connectors/`, `${appId}/exo/v1/requests/`, `${appId}/exo/v1/jobs/`], actions: ['get', 'put', 'list', 'del', 'metadata'], root: true },
    sql: { databases: ['threads', 'canvas', 'connectors', 'home_feed', 'details', 'summaries', 'transcripts'].map(x => `${appId}/${x}`), actions: ['read', 'write', 'schema'], prefixes: [`${appId}/feed/`], foreignDatabases: ['xyz.tinycloud.sample.healthlog/healthlog', 'xyz.tinycloud.sample.recipes/recipes'] },
    hooks: { paths: [`sql/${appId}/feed/`, `sql/${appId}/home_feed`, `sql/${appId}/threads`], actions: ['subscribe'] },
    maxDelegationTtlSeconds: 3600, grantLifetimeSeconds: 30 * 86400, siweDomain: 'openkey.so' };
  let directory: string;
  let database: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let address: string;
  let userId: string;
  const call = (path: string, body?: unknown, headers: Record<string, string> = {}) => app.fetch(new Request(api + path, {
    method: 'POST', headers: { origin: 'https://openkey.test', 'content-type': 'application/json', ...headers }, body: JSON.stringify(body ?? {}),
  }));
  const intentCookie = async () => (await call('/api/review-account/delete-intent')).headers.get('set-cookie')!.split(';')[0]!;
  const events = async () => database.accountDeletionEvent.findMany();

  beforeAll(async () => {
    directory = await mkdtemp('/var/tmp/reviewer-delete-event-db.');
    const pg = new PGlite(directory);
    try {
      for (const name of (await readdir(join(root, 'packages/db/prisma/migrations'))).sort()) {
        if (name !== 'migration_lock.toml') await pg.exec(await readFile(join(root, 'packages/db/prisma/migrations', name, 'migration.sql'), 'utf8'));
      }
    } finally { await pg.close(); }
    process.env.DATABASE_URL = 'pglite:' + directory;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    database = (await import('../auth')).prisma;
    app = (await import('../index')).default;
    await database.oauthClient.create({ data: { id: randomUUID(), clientId, name: 'Home fixture', public: true, type: 'native', tokenEndpointAuthMethod: 'none', redirectUris: [redirect], scopes: ['openid', 'email', 'offline_access', 'tinycloud:delegation'], contacts: [], tinycloudNativeDelegation: ceiling } });
    userId = 'reviewer-delete-event-owner';
    await database.user.create({ data: { id: userId, email, name: 'App review', emailVerified: true, reviewerHoldAt: new Date() } });
    const tee = await import('@openkey/tee');
    const privateKey = tee.generatePrivateKey();
    address = tee.getAddressFromPrivateKey(privateKey);
    const sealingContext = (await import('../services/key-sealing')).createSealingContext();
    const key = await database.ethereumKey.create({ data: { id: 'reviewer-delete-event-key', userId, address, publicKey: address,
      sealingContext, sealedBlob: await tee.seal(privateKey, await tee.createTeeClient().deriveKey('openkey/key/' + sealingContext)), isCanonicalTinyCloud: true } });
    const spaceId = `tinycloud:pkh:eip155:1:${address}:applications`;
    await database.reviewerAccount.update({ where: { store: 'apple' }, data: { userId, keyId: key.id, spaceId, clientId, redirectUri: redirect, nodeHost: host, seededAt: new Date() } });
    await database.tinyCloudBootstrapState.create({ data: { userId, keyId: key.id, address, chainId: 1, tinycloudHost: host,
      bootstrapVersion: 'test', status: 'complete', checkedAt: new Date(), completedAt: new Date() } });
    await (await import('../services/reviewer-accounts')).installReviewer(database, 'apple', code);
  }, 90_000);
  afterAll(async () => { await database?.$disconnect(); if (directory) await rm(directory, { recursive: true, force: true }); });

  test('a refused reviewer deletion writes no event; the accepted one writes one with the account\'s address', async () => {
    const cookie = await intentCookie();
    const wrongCode = await call('/api/review-account/delete', { email, code: randomBytes(32).toString('base64url'), confirmation: 'DELETE MY ACCOUNT' }, { cookie });
    expect(wrongCode.status).toBe(403);
    const wrongText = await call('/api/review-account/delete', { email, code, confirmation: 'delete my account' }, { cookie: await intentCookie() });
    expect(wrongText.status).toBe(403);
    expect(await database.user.count({ where: { id: userId } })).toBe(1);
    expect(await events()).toEqual([]);

    const deleted = await call('/api/review-account/delete', { email, code, confirmation: 'DELETE MY ACCOUNT' }, { cookie: await intentCookie() });
    expect(deleted.status, await deleted.clone().text()).toBe(200);
    expect(await database.user.count({ where: { id: userId } })).toBe(0);
    const written = await events();
    expect(written).toHaveLength(1);
    expect(written[0]!.addresses).toEqual([address]);
  }, 30_000);
}
