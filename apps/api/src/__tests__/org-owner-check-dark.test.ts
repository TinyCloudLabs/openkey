import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { CompactSign, generateKeyPair } from 'jose';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { PrismaClient } from '@openkey/db';

// TC-128 OK-1, flag off, through the real API index: with ORG_KEY_CUSTODY_ENABLED unset or "false" the
// owner-check path answers 404 before any token work, returns no Access-Control-* header, and never fetches
// the issuer DID document. The router-level test covers the same flag values without the real index.
const root = resolve(import.meta.dir, '../../../..');
const ISSUER_DID = 'did:web:issuer.credentials.org';
const ISSUER_DID_URL = 'https://issuer.credentials.org/.well-known/did.json';
const childMode = process.env.OPENKEY_OWNER_CHECK_DARK_CHILD;

if (childMode === undefined) {
  for (const mode of ['unset', 'false']) {
    test(`actual API index answers the owner-check path 404 with the flag ${mode}: no CORS header, no DID fetch`, async () => {
      const env: Record<string, string | undefined> = { ...process.env, OPENKEY_OWNER_CHECK_DARK_CHILD: mode, NODE_ENV: 'test', TEE_MODE: 'development', BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'owner-check-dark-isolated-fixture-secret', WEBAUTHN_RP_ID: 'openkey.so', WEBAUTHN_ORIGIN: 'https://openkey.so', CORS_ORIGIN: 'http://localhost:5173', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '' };
      delete env.ORG_KEY_CUSTODY_ENABLED;
      if (mode === 'false') env.ORG_KEY_CUSTODY_ENABLED = 'false';
      const child = Bun.spawn([process.execPath, '--no-env-file', 'test', import.meta.path], { cwd: root, env, stdout: 'pipe', stderr: 'pipe' });
      const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(code, stdout + stderr).toBe(0);
    }, 60_000);
  }
} else {
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch(request: Request): Response | Promise<Response> };
  let token: string;
  const originalFetch = globalThis.fetch;
  const issuerFetches: string[] = [];
  beforeAll(async () => {
    // The mounted router resolves the issuer DID through the global fetch. Count that call and never let it reach the network.
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url === ISSUER_DID_URL || url.includes('issuer.credentials.org')) {
        issuerFetches.push(url);
        return Promise.resolve(new Response('issuer DID fetch is not allowed here', { status: 500 }));
      }
      return originalFetch(input, init);
    }) as typeof fetch;
    // Syntactically valid, unexpired owner-check JWS; the issuer key is a throwaway, so it could never verify against a real DID.
    const { privateKey } = await generateKeyPair('EdDSA', { extractable: true });
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: ISSUER_DID, aud: 'https://api.openkey.so', purpose: 'org-owner-check/v1', keyId: 'key-1', account: `0x${'a'.repeat(40)}`, jti: 'dark-jti-1', iat: now, exp: now + 60 };
    token = await new CompactSign(new TextEncoder().encode(JSON.stringify(claims))).setProtectedHeader({ alg: 'EdDSA', kid: `${ISSUER_DID}#key-1`, typ: 'org-owner-check+jwt' }).sign(privateKey);

    directory = await mkdtemp(join(tmpdir(), 'owner-check-dark-'));
    const engine = new PGlite(directory);
    try {
      const migrationRoot = join(root, 'packages/db/prisma/migrations');
      const names = (await readdir(migrationRoot, { withFileTypes: true })).filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
      for (const name of names) await engine.exec(await readFile(join(migrationRoot, name, 'migration.sql'), 'utf8'));
    } finally { await engine.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    // Dynamic imports: DATABASE_URL and the fetch counter must be in place before the real index module evaluates.
    ({ prisma } = await import('../auth'));
    app = (await import('../index')).default;
  }, 30_000);
  afterAll(async () => {
    globalThis.fetch = originalFetch;
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  function request(path: string, method: string, headers: Record<string, string>) {
    return app.fetch(new Request('https://api.openkey.test' + path, { method, headers }));
  }
  function corsHeaders(response: Response): string[] {
    return [...response.headers.keys()].filter((name) => name.toLowerCase().startsWith('access-control-'));
  }
  test('the flag is off in this boot', () => {
    const expected = childMode === 'false' ? 'false' : undefined;
    expect(process.env.ORG_KEY_CUSTODY_ENABLED).toBe(expected);
  });
  test('POST with a valid-looking Bearer token answers 404 Not found, with no CORS header and no issuer DID fetch', async () => {
    // Control: the same Origin on another path still gets the credentialed policy, so the no-CORS assertions can fail.
    expect((await request('/api/internal/metrics', 'GET', { origin: 'http://localhost:5173' })).headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
    for (const path of ['/api/internal/org-owner-check', '/api/internal/org-owner-check/']) {
      for (const origin of [undefined, 'http://localhost:5173', 'https://openkey.so', 'https://credentials.org']) {
        const response = await request(path, 'POST', { authorization: `Bearer ${token}`, ...(origin ? { origin } : {}) });
        expect(response.status).toBe(404);
        expect(await response.json()).toEqual({ error: 'Not found' });
        expect(corsHeaders(response)).toEqual([]);
      }
      const preflight = await request(path, 'OPTIONS', { origin: 'https://openkey.so', 'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization' });
      expect(corsHeaders(preflight)).toEqual([]);
    }
    expect(issuerFetches).toEqual([]);
    expect(await prisma.keyGrant.count()).toBe(0);
  });
}
