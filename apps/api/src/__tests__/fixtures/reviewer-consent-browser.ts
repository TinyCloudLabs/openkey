// Real-provider fixture for the hosted consent browser regression. No external services.
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
    NODE_ENV: 'test', TEE_MODE: 'development', DATABASE_URL: 'pglite:' + join(process.env.HOME!, 'db'),
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
  const callback = 'https://example.test/reviewer-callback';
  const resource = 'https://mcp.tinycloud.xyz/chatgpt/mcp';
  const registration = await call('/api/auth/oauth2/register', {
    client_name: 'Reviewer consent fixture', redirect_uris: [callback], token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
  });
  const { client_id: clientId } = await registration.json() as { client_id: string };
  if (registration.status !== 200 || !clientId) throw new Error('Registration failed');
  await database.oauthClient.update({ where: { clientId }, data: { clientSecret: 'synthetic-private-client-field' } });
  await database.user.create({ data: { id: 'reviewer-browser', email: 'openai-review@tinycloud.xyz', name: 'App review', emailVerified: true, autoSignEnabled: false, reviewerHoldAt: new Date() } });
  await database.reviewerAccount.update({ where: { store: 'openai' }, data: {
    userId: 'reviewer-browser', clientId, redirectUri: callback, resource,
    callbackUri: 'https://mcp.tinycloud.xyz/chatgpt/connect/callback', nodeHost: 'https://node.tinycloud.xyz',
    keyId: 'reviewer-browser-key', spaceId: 'reviewer-browser-space', seededAt: new Date(),
  } });
  const { installReviewer } = await import('../../services/reviewer-accounts');
  const code = randomBytes(32).toString('base64url');
  await installReviewer(database, 'openai', code);
  const query = new URLSearchParams({ client_id: clientId, redirect_uri: callback, resource,
    response_type: 'code', scope: 'openid email tinycloud:mcp', state: 'reviewer-browser-state',
    code_challenge_method: 'S256', code_challenge: randomBytes(32).toString('base64url') });
  const authorization = await call('/api/auth/oauth2/authorize?' + query);
  const signedQuery = new URL(authorization.headers.get('location')!).searchParams.toString();
  const signIn = await call('/api/auth/sign-in/reviewer', { email: 'openai-review@tinycloud.xyz', code, oauth_query: signedQuery });
  if (signIn.status !== 200) throw new Error('Sign-in failed');
  const cookie = signIn.headers.getSetCookie().map((value) => value.split(';')[0]).find((value) => value!.includes('session_token='))!;
  const consent = await call('/api/auth/oauth2/authorize?' + query, undefined, cookie);
  if (consent.status !== 302) throw new Error('Consent redirect failed');
  output(JSON.stringify({ api, clientId, cookie, consentQuery: new URL(consent.headers.get('location')!).searchParams.toString() }) + '\n');
}
process.once('SIGTERM', () => { server.stop(true); void database?.$disconnect().finally(() => process.exit(0)); });
main().catch(() => { output(JSON.stringify({ error: 'Reviewer browser fixture failed' }) + '\n'); process.exit(1); });
