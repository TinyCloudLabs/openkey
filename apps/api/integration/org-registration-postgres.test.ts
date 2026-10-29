import { afterAll, beforeAll, expect, test } from 'bun:test';
import type { Server } from 'bun';
import { randomBytes, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { Hono } from 'hono';
import { serializeSignedCookie } from 'better-call';
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT, type JWK } from 'jose';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { createTeeClient } from '@openkey/tee';
import type { SessionContext } from '../src/middleware/session';
import { addPasskey, assertionFor, type PasskeyFixture } from '../src/__tests__/org-keys-fixtures';
import { createOrgRegistrationHandler, type OrgRegistrationActor, type OrgRegistrationProof, type OrgRegistrationResponse } from '../src/services/org-registration';
import { OrgKeyRefusal } from '../src/services/org-keys';

const root = resolve(import.meta.dir, '../../..');
const configured = process.env.DATABASE_URL;
if (!configured || !['127.0.0.1', 'localhost'].includes(new URL(configured).hostname) || new URL(configured).pathname !== '/s1b_fixture') {
  throw new Error('This integration test requires its owned loopback s1b_fixture PostgreSQL service');
}
const originalSchema = process.env.OPENKEY_DATABASE_SCHEMA;
const databaseName = `s1b_registration_${randomUUID().replaceAll('-', '')}`;
const target = new URL(configured);
target.pathname = `/${databaseName}`;
target.search = '';
const owner = `owner-${randomUUID()}`;
const origin = 'https://openkey.so';
const rpID = 'openkey.so';
const lockId = 1281518;
let admin: PrismaClient;
let control: PrismaClient;
let database: PrismaClient;
let server: Server<undefined>;
let cookie: string;
let body: { intentJws: string; registrationId: string; orgId: string; nonce: string; handle: string; orgName: string };
let credential: PasskeyFixture;
let jwks: { keys: JWK[] };
let blockedGraphObserved = false;
interface HttpOutcome { status: number; body: OrgRegistrationResponse['body'] | { code: string } }

beforeAll(async () => {
  admin = createPrismaClient({ connectionString: configured });
  await admin.$executeRawUnsafe(`CREATE DATABASE "${databaseName}"`);
  control = createPrismaClient({ connectionString: target.toString() });
  process.env.DATABASE_URL = target.toString();
  delete process.env.OPENKEY_DATABASE_SCHEMA;
  const migration = Bun.spawn([process.execPath, '--no-env-file', 'run', 'db:migrate:apply'], {
    cwd: root, env: process.env, stdout: 'pipe', stderr: 'pipe',
  });
  const [out, err, code] = await Promise.all([new Response(migration.stdout).text(), new Response(migration.stderr).text(), migration.exited]);
  expect(code, out + err).toBe(0);
  // A freshly migrated isolated database must exist before the actual auth module captures DATABASE_URL.
  const { auth, prisma } = await import('../src/auth');
  const { requireSession } = await import('../src/middleware/session');
  database = prisma;
  const token = randomBytes(32).toString('base64url');
  const sessionId = randomUUID();
  await database.user.create({ data: { id: owner, email: `${owner}@example.test`, emailVerified: true } });
  await database.session.create({ data: { id: sessionId, userId: owner, token, expiresAt: new Date(Date.now() + 3_600_000) } });
  const state = { passkeys: [] as Record<string, unknown>[] };
  credential = addPasskey(state, owner);
  await database.passkey.create({ data: { id: `${owner}-passkey`, userId: owner, credentialID: credential.credentialID, publicKey: state.passkeys[0]!.publicKey as string, counter: 0, deviceType: 'singleDevice', backedUp: false } });
  const context = await auth.$context;
  cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, token, context.secret)).split(';')[0]!;
  jwks = await auth.api.getJwks();
  const oc = await generateKeyPair('EdDSA', { extractable: true });
  const issuer = 'did:web:issuer.credentials.org';
  const kid = `${issuer}#controller`;
  const document = { id: issuer, assertionMethod: [kid], verificationMethod: [{ id: kid, controller: issuer, publicKeyJwk: await exportJWK(oc.publicKey) }] };
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: issuer, aud: 'https://api.openkey.so', registrationId: randomUUID(), orgId: `o${'c'.repeat(26)}`, nonce: randomBytes(32).toString('base64url'), handle: 'pg-registration', displayName: 'PostgreSQL registration', purpose: 'org-registration/v1', iat: now, exp: now + 600 };
  const intentJws = await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', kid, typ: 'org-registration-intent+jwt' }).sign(oc.privateKey);
  body = { intentJws, registrationId: claims.registrationId, orgId: claims.orgId, nonce: claims.nonce, handle: claims.handle, orgName: claims.displayName };
  const jwtApi = auth.api as typeof auth.api & {
    signJWT(input: { body: { payload: OrgRegistrationProof } }): Promise<{ token: string }>;
  };
  const handle = createOrgRegistrationHandler(database, createTeeClient(), {
    fetch: async () => new Response(JSON.stringify(document)),
    signProof: async payload => (await jwtApi.signJWT({ body: { payload } })).token,
  });
  const app = new Hono<SessionContext>();
  app.use('*', requireSession);
  app.post('/', async c => {
    try {
      const actor: OrgRegistrationActor = { userId: c.get('user').id, sessionId: c.get('session').id, origin: c.req.header('origin'), rpID, expectedOrigin: origin };
      const result = await handle(await c.req.text(), actor);
      // This private harness tests the internal producer before the separate server-to-OC completion stage.
      return c.json(result.body, result.status);
    } catch (error) {
      if (error instanceof OrgKeyRefusal) return c.json({ code: error.code }, error.status);
      throw error;
    }
  });
  server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: app.fetch });
  await database.$executeRawUnsafe(`CREATE FUNCTION s1b_counter_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(${lockId}); RETURN NEW; END $$`);
  await database.$executeRawUnsafe('CREATE TRIGGER s1b_counter_barrier BEFORE UPDATE OF counter ON passkey FOR EACH ROW EXECUTE FUNCTION s1b_counter_barrier()');
}, 30_000);

afterAll(async () => {
  await server?.stop(true);
  await database?.$disconnect();
  await control?.$disconnect();
  if (admin) {
    await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${databaseName}"`);
    await admin.$disconnect();
  }
  process.env.DATABASE_URL = configured;
  if (originalSchema === undefined) delete process.env.OPENKEY_DATABASE_SCHEMA;
  else process.env.OPENKEY_DATABASE_SCHEMA = originalSchema;
});

async function post(input: unknown): Promise<HttpOutcome> {
  const response = await fetch(`http://127.0.0.1:${server.port}/`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' }, body: JSON.stringify(input) });
  return { status: response.status, body: await response.json() };
}

test('a committed concurrent registration wins after counter rollback without a duplicate controller', async () => {
  const first = await post(body);
  const second = await post(body);
  expect([first.status, second.status]).toEqual([200, 200]);
  if (!('registrationChallenge' in first.body) || !('registrationChallenge' in second.body)) throw new Error('Producer did not issue both consent challenges');
  let approvals: Promise<HttpOutcome>[] = [];
  await control.$transaction(async tx => {
    await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(${lockId})`);
    const [{ pid }] = await tx.$queryRawUnsafe<Array<{ pid: number }>>('SELECT pg_backend_pid() AS pid');
    approvals = [
      post({ ...body, challengeNonce: first.body.registrationChallenge.challengeNonce, assertion: assertionFor(credential, first.body.registrationChallenge.challenge, { origin, rpID, counter: 1 }) }),
      post({ ...body, challengeNonce: second.body.registrationChallenge.challengeNonce, assertion: assertionFor(credential, second.body.registrationChallenge.challenge, { origin, rpID, counter: 2 }) }),
    ];
    const deadline = Date.now() + 3_000;
    while (Date.now() < deadline) {
      const graph = await tx.$queryRawUnsafe<Array<{ pid: number; blockers: number[] }>>('SELECT DISTINCT pid, pg_blocking_pids(pid) AS blockers FROM pg_locks WHERE pid IS NOT NULL AND database = (SELECT oid FROM pg_database WHERE datname = current_database())');
      const firstBlocked = graph.find(row => row.blockers.includes(pid!));
      if (firstBlocked && graph.some(row => row.pid !== firstBlocked.pid && row.blockers.includes(firstBlocked.pid))) { blockedGraphObserved = true; break; }
      await new Promise<void>(resolve => setImmediate(resolve));
    }
  }); // Releasing this transaction's advisory lock permits the first producer to commit.
  const responses = await Promise.all(approvals);
  process.stdout.write(JSON.stringify({ synthetic: true, blockedGraphObserved, statuses: responses.map(response => response.status) }) + '\n');
  expect(blockedGraphObserved).toBe(true);
  expect(responses.map(response => response.status).sort()).toEqual([200, 201]);
  const [one, two] = responses;
  if (!one || !two || !('key' in one.body) || !('key' in two.body)) throw new Error('Producer did not return the committed key');
  expect(one.body.key).toEqual(two.body.key);
  expect(one.body.registrationProof === two.body.registrationProof).toBe(true);
  const verified = await jwtVerify(one.body.registrationProof, createLocalJWKSet(jwks), { issuer: 'https://api.openkey.so/api/auth', audience: 'https://witness.credentials.org' });
  expect(verified.payload).toMatchObject({ sub: owner, registrationId: body.registrationId, controllerDid: one.body.key.controllerDid });
  expect(await database.ethereumKey.count({ where: { custody: 'ORG' } })).toBe(1);
  expect(await database.keyGrant.count({ where: { role: 'OWNER', granteeUserId: owner } })).toBe(1);
  expect(await database.orgKeyRegistration.count()).toBe(1);
  console.log('Observed both PostgreSQL lock waiters; exactly one committed registration and immutable winner proof.');
}, 15_000);
