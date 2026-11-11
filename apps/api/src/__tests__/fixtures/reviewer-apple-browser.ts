// Real-provider fixture for Apple reviewer screens. No external services.
import { PGlite } from '@electric-sql/pglite';
import { randomBytes } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { PrismaClient } from '@openkey/db';

const output = process.stdout.write.bind(process.stdout);
process.stdout.write = (() => true) as typeof process.stdout.write;
const root = process.cwd();
let database: PrismaClient;
let app: { fetch: (request: Request) => Response | Promise<Response> } | undefined;
const server = Bun.serve({ hostname: '127.0.0.1', port: 0,
  fetch: (request) => app ? app.fetch(request) : new Response(null, { status: 503 }) });
const api = server.url.origin;
const origin = process.env.OPENKEY_BROWSER_ORIGIN!;

async function main() {
  Object.assign(process.env, {
    NODE_ENV: 'test', TEE_MODE: 'development', APPLE_REVIEW_ENABLED: 'true', DATABASE_URL: 'pglite:' + join(process.env.HOME!, 'db'),
    BETTER_AUTH_URL: api, BETTER_AUTH_SECRET: randomBytes(32).toString('base64url'),
    WEBAUTHN_RP_ID: 'localhost', WEBAUTHN_ORIGIN: origin, CORS_ORIGIN: origin,
    RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
  });
  const pg = new PGlite(join(process.env.HOME!, 'db'));
  const migrationsRoot = join(root, 'packages/db/prisma/migrations');
  try {
    for (const entry of (await readdir(migrationsRoot, { withFileTypes: true })).filter((entry) => entry.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
      await pg.exec(await readFile(join(migrationsRoot, entry.name, 'migration.sql'), 'utf8'));
    }
  } finally { await pg.close(); }
  // The fixture reaches no node, mail service or third-party OAuth provider.
  globalThis.fetch = (() => Promise.reject(new Error('External network disabled'))) as unknown as typeof fetch;
  database = (await import('../../auth')).prisma;
  app = (await import('../../index')).default;
  const call = (path: string, body?: unknown, cookie?: string) => app!.fetch(new Request(api + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { origin, 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
  const { APPLE_REVIEW_CLIENT_ID: clientId, REVIEWER_HOME_PERMISSIONS } = await import('../../services/reviewer-apple-policy');
  const callback = 'xyz.tinycloud.exo://openkey/callback';
  const appId = 'xyz.tinycloud.tinychat';
  const ceiling = { version: 1, appId, tinycloudHost: 'https://tee.node.tinycloud.xyz',
    kv: { paths: [`${appId}/threads/`, `${appId}/connectors/`, `${appId}/exo/v1/requests/`, `${appId}/exo/v1/jobs/`], actions: ['get', 'put', 'list', 'del', 'metadata'], root: true },
    sql: { databases: ['threads', 'canvas', 'connectors', 'home_feed', 'details', 'summaries', 'transcripts'].map(x => `${appId}/${x}`), actions: ['read', 'write', 'schema'], prefixes: [`${appId}/feed/`], foreignDatabases: ['xyz.tinycloud.sample.healthlog/healthlog', 'xyz.tinycloud.sample.recipes/recipes'] },
    hooks: { paths: [`sql/${appId}/feed/`, `sql/${appId}/home_feed`, `sql/${appId}/threads`], actions: ['subscribe'] },
    maxDelegationTtlSeconds: 3600, grantLifetimeSeconds: 30 * 86400, siweDomain: 'openkey.so' };
  await database.oauthClient.create({ data: { id: 'apple-browser-client', clientId, name: 'TinyCloud Home', public: true, type: 'native', tokenEndpointAuthMethod: 'none', redirectUris: [callback], scopes: ['openid', 'email', 'offline_access', 'tinycloud:delegation'], contacts: [], tinycloudNativeDelegation: ceiling } });
  await database.user.create({ data: { id: 'apple-browser', email: 'appreview@tinycloud.xyz', name: 'App review', emailVerified: true, reviewerHoldAt: new Date() } });
  const { generatePrivateKey, getAddressFromPrivateKey, seal, createTeeClient } = await import('@openkey/tee');
  const privateKey = generatePrivateKey();
  const address = getAddressFromPrivateKey(privateKey);
  const sealingContext = (await import('../../services/key-sealing')).createSealingContext();
  await database.ethereumKey.create({ data: { id: 'apple-browser-key', userId: 'apple-browser', address, publicKey: address, isCanonicalTinyCloud: true, sealingContext,
    sealedBlob: await seal(privateKey, await createTeeClient().deriveKey('openkey/key/' + sealingContext)) } });
  await database.tinyCloudBootstrapState.create({ data: { userId: 'apple-browser', keyId: 'apple-browser-key', address, chainId: 1, tinycloudHost: ceiling.tinycloudHost, bootstrapVersion: 'fixture', status: 'complete', checkedAt: new Date() } });
  await database.reviewerAccount.update({ where: { store: 'apple' }, data: { userId: 'apple-browser', clientId, redirectUri: callback, nodeHost: ceiling.tinycloudHost,
    keyId: 'apple-browser-key', spaceId: `tinycloud:pkh:eip155:1:${address}:applications`, seededAt: new Date() } });
  await (await import('../../services/reviewer-accounts')).installReviewer(database, 'apple', randomBytes(32).toString('base64url'));
  const { generateKeyPairSync } = await import('node:crypto');
  const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const par = await app!.fetch(new Request(api + '/api/auth/oauth2/par', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, response_type: 'code', redirect_uri: callback, state: randomBytes(24).toString('base64url'),
      code_challenge: randomBytes(32).toString('base64url'), code_challenge_method: 'S256', scope: 'openid email offline_access tinycloud:delegation',
      login_method: 'email', login_hint: 'appreview@tinycloud.xyz',
      authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: jwk, permissions: REVIEWER_HOME_PERMISSIONS, ttl_seconds: 3600 }]) }) }));
  if (par.status !== 201) throw new Error('PAR failed');
  const { request_uri } = await par.json() as { request_uri: string };
  const authorization = await call('/api/auth/oauth2/authorize?' + new URLSearchParams({ client_id: clientId, request_uri }));
  if (authorization.status !== 302) throw new Error('Authorize failed');
  output(JSON.stringify({ api, loginQuery: new URL(authorization.headers.get('location')!).searchParams.toString() }) + '\n');
}
process.once('SIGTERM', () => { server.stop(true); void database?.$disconnect().finally(() => process.exit(0)); });
main().catch(() => { output(JSON.stringify({ error: 'Reviewer browser fixture failed' }) + '\n'); process.exit(1); });
