import { expect, test } from 'bun:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';

// A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
if (!process.env.TC_SIGN_ORIGIN_CHILD) {
  test('sign origin gate runs against a real cookie session and bearer token', async () => {
    const directory = await mkdtemp('/var/tmp/openkey-sign-origin-');
    console.log(`private integration directory: ${directory}`);
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC_SIGN_ORIGIN_CHILD: directory, HOME: directory, TMPDIR: directory,
          BUN_INSTALL_CACHE_DIR: join(directory, 'bun-cache'), NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: 'http://localhost:3324', BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
          WEBAUTHN_ORIGIN: 'https://openkey.example', WEBAUTHN_RP_ID: 'localhost', CORS_ORIGIN: 'https://openkey.example,https://console.openkey.example,https://staging.openkey.example', CONSOLE_ORIGIN: 'https://console.openkey.example',
          TINYCLOUD_BOOTSTRAP_ON_SIGN: 'off',
          RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
          DATABASE_URL: `pglite:${join(directory, 'db')}` },
        stdout: 'pipe', stderr: 'pipe',
      });
      const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(code, stdout + stderr).toBe(0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }, 120_000);
} else {
  test('sign and sign-typed-data bind a cookie session to an OpenKey origin', async () => {
    const directory = process.env.TC_SIGN_ORIGIN_CHILD!;
    const root = resolve(import.meta.dir, '../../../..');
    const database = new PGlite(join(directory, 'db'));
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    await database.close();
    // The app's auth/database/TEE singletons must capture the isolated child
    // environment only after its tracked schema exists, not at static import.
    const { createPrismaClient } = await import('@openkey/db');
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const { auth } = await import('../auth');
    const app = (await import('../index')).default;
    const prisma = createPrismaClient();
    const userId = randomUUID();
    const user = await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, emailVerified: true } });
    const privateKey = generatePrivateKey();
    const address = getAddressFromPrivateKey(privateKey);
    const sealingContext = randomBytes(32).toString('base64url');
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    const ownerKey = await prisma.ethereumKey.create({ data: { userId: user.id, address, publicKey: '0x1', sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
    const token = randomBytes(32).toString('base64url');
    await prisma.session.create({ data: { id: randomUUID(), userId, token, expiresAt: new Date(Date.now() + 3600_000) } });
    const authContext = await auth.$context;
    const cookie = (await serializeSignedCookie(authContext.authCookies.sessionToken.name, token, authContext.secret)).split(';')[0]!;

    // The account and console origins are on the credentialed CORS allowlist.
    const OPENKEY = 'https://openkey.example';
    const SIBLING = 'https://sibling.openkey.so';
    const EMBEDDER = 'https://embedding-app.example';
    const FOREIGN = 'https://attacker-site.example';
    const apiOrigin = process.env.BETTER_AUTH_URL!;
    // The console origin is on the credentialed allowlist (CORS_ORIGIN above)
    // but must not reach a signing route.
    const CONSOLE = 'https://console.openkey.example';
    const STAGING = 'https://staging.openkey.example';


    function siweFor(origin: string): string {
      const { host } = new URL(origin);
      return [
        `${host} wants you to sign in with your Ethereum account:`,
        address,
        '',
        'Sign in',
        '',
        `URI: ${origin}`,
        'Version: 1',
        'Chain ID: 1',
        'Nonce: abcdef12345678',
        'Issued At: 2026-11-09T00:00:00.000Z',
      ].join('\n');
    }

    const typedData = {
      domain: { name: 'Example', version: '1' },
      types: { Mail: [{ name: 'contents', type: 'string' }] },
      primaryType: 'Mail',
      message: { contents: 'hi' },
    };

    function post(path: string, body: unknown, headers: Record<string, string> = {}) {
      return app.fetch(new Request(apiOrigin + path, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(body),
      }));
    }
    const sign = (body: unknown, headers: Record<string, string> = {}) =>
      post(`/api/keys/${ownerKey.id}/sign`, body, headers);
    const signTyped = (body: unknown, headers: Record<string, string> = {}) =>
      post(`/api/keys/${ownerKey.id}/sign-typed-data`, body, headers);

    // (a) A cookie-session sign whose Origin header differs from the
    // caller-claimed requestOrigin: the SIWE names the origin the caller chose
    // and passes its own guard, so only the header can refute it.
    const forged = await sign(
      { message: siweFor(FOREIGN), requestOrigin: FOREIGN },
      { cookie, origin: EMBEDDER },
    );
    expect(forged.status).toBe(403);

    // A cookie request from any non-OpenKey origin is refused even when the
    // claimed requestOrigin agrees with the header.
    const foreignMatched = await sign(
      { message: siweFor(FOREIGN), requestOrigin: FOREIGN },
      { cookie, origin: FOREIGN },
    );
    expect(foreignMatched.status).toBe(403);

    // (b) A sibling host carries the shared session cookie but is not the
    // OpenKey web app, so its requests are refused.
    const sibling = await sign(
      { message: siweFor(SIBLING), requestOrigin: SIBLING },
      { cookie, origin: SIBLING },
    );
    expect(sibling.status).toBe(403);

    // A non-browser cookie caller sends no Origin and is refused too.
    const noOrigin = await sign({ message: 'hello' }, { cookie });
    expect(noOrigin.status).toBe(403);

    // (c) sign-typed-data shares the same gate.
    const typedSibling = await signTyped(typedData, { cookie, origin: SIBLING });
    expect(typedSibling.status).toBe(403);
    const typedForeign = await signTyped(typedData, { cookie, origin: FOREIGN });
    expect(typedForeign.status).toBe(403);
    const typedNoOrigin = await signTyped(typedData, { cookie });
    expect(typedNoOrigin.status).toBe(403);

    // The console origin is allowlisted for CORS and auth (it is in
    // CORS_ORIGIN and CONSOLE_ORIGIN above) but must not sign.
    const consoleSign = await sign(
      { message: siweFor(CONSOLE), requestOrigin: CONSOLE },
      { cookie, origin: CONSOLE },
    );
    expect(consoleSign.status).toBe(403);
    const consoleTyped = await signTyped(typedData, { cookie, origin: CONSOLE });
    expect(consoleTyped.status).toBe(403);

    const previousCorsOrigin = process.env.CORS_ORIGIN;
    const previousConsoleOrigin = process.env.CONSOLE_ORIGIN;
    const previousWebauthnOrigin = process.env.WEBAUTHN_ORIGIN;

    // With no configured account origin, a console-only CORS configuration
    // must fail closed rather than falling back to the console.
    process.env.CORS_ORIGIN = CONSOLE;
    process.env.CONSOLE_ORIGIN = CONSOLE;
    delete process.env.WEBAUTHN_ORIGIN;
    const consoleOnlySign = await sign({ message: 'hello' }, { cookie, origin: CONSOLE });
    expect(consoleOnlySign.status).toBe(403);

    // When the account and console origins coincide, preserve the account.
    process.env.CORS_ORIGIN = OPENKEY;
    process.env.CONSOLE_ORIGIN = OPENKEY;
    process.env.WEBAUTHN_ORIGIN = OPENKEY;
    const sharedOriginSign = await sign({ message: 'hello' }, { cookie, origin: OPENKEY });
    expect(sharedOriginSign.status).toBe(200);
    if (previousCorsOrigin === undefined) delete process.env.CORS_ORIGIN;
    else process.env.CORS_ORIGIN = previousCorsOrigin;
    if (previousConsoleOrigin === undefined) delete process.env.CONSOLE_ORIGIN;
    else process.env.CONSOLE_ORIGIN = previousConsoleOrigin;
    if (previousWebauthnOrigin === undefined) delete process.env.WEBAUTHN_ORIGIN;
    else process.env.WEBAUTHN_ORIGIN = previousWebauthnOrigin;

    // (d) First-party flows still sign.
    const panelSign = await sign({ message: 'hello' }, { cookie, origin: OPENKEY });
    expect(panelSign.status).toBe(200);
    expect(await panelSign.json()).toMatchObject({ address, format: 'personal_sign' });

    // The widget signs an embedder's SIWE: the request runs on the OpenKey
    // origin while requestOrigin names the verified postMessage sender.
    const widgetSign = await sign(
      { message: siweFor(EMBEDDER), requestOrigin: EMBEDDER },
      { cookie, origin: OPENKEY },
    );
    expect(widgetSign.status).toBe(200);

    const widgetBearer = await sign(
      { message: siweFor(EMBEDDER), requestOrigin: EMBEDDER },
      { authorization: `Bearer ${token}`, origin: OPENKEY },
    );
    expect(widgetBearer.status).toBe(200);

    const typedPanel = await signTyped(typedData, { cookie, origin: OPENKEY });
    expect(typedPanel.status).toBe(200);
    const typedBearer = await signTyped(
      typedData,
      { authorization: `Bearer ${token}`, origin: OPENKEY },
    );
    expect(typedBearer.status).toBe(200);

    const GATE_ERROR = 'Managed-key signing requires an OpenKey browser origin';

    // The gate does not depend on how the router is mounted: any credential
    // presented from outside the OpenKey origins is refused before auth runs.
    const cookiePlusJunkBearer = await sign(
      { message: 'hello' },
      { cookie, authorization: 'Bearer junk', origin: SIBLING },
    );
    expect(cookiePlusJunkBearer.status).toBe(403);
    // The bearer middleware already refuses junk credentials; this pins the
    // status, not which layer answered.

    // The sibling routes get the same boundary. Unknown ids reach the handler
    // (404 past the gate); sibling, missing, and foreign Origins do not.
    const nostrGrant = (headers: Record<string, string>) =>
      post('/api/keys/nostr/key_missing/grants', { clientOrigin: 'https://client.example', kinds: [9] }, headers);
    const nostrSign = (headers: Record<string, string>) =>
      post('/api/keys/nostr/key_missing/sign-event', { clientOrigin: 'https://client.example', event: {} }, headers);
    expect((await nostrGrant({ cookie, origin: SIBLING })).status).toBe(403);
    expect((await nostrGrant({ cookie })).status).toBe(403);
    expect((await nostrSign({ cookie, origin: SIBLING })).status).toBe(403);
    expect((await nostrSign({ cookie })).status).toBe(403);
    expect((await nostrGrant({ cookie, origin: OPENKEY })).status).toBe(404);
    expect((await nostrSign({ cookie, origin: OPENKEY })).status).toBe(404);

    // /api/delegate/sign: the cookie-session signer path gets the gate; the
    // OAuth bearer path stays open to any origin.
    const delegateSign = (body: unknown, headers: Record<string, string>) =>
      post('/api/delegate/sign', body, headers);
    const minimal = { address, chainId: 1, message: 'hello', type: 'message' };
    for (const headers of [{ cookie, origin: SIBLING }, { cookie }] as Array<Record<string, string>>) {
      const refused = await delegateSign(minimal, headers);
      expect(refused.status).toBe(403);
      expect(await refused.json()).toMatchObject({ error: GATE_ERROR });
    }
    const delegateCookieOk = await delegateSign(minimal, { cookie, origin: OPENKEY });
    expect(await delegateCookieOk.json()).not.toMatchObject({ error: GATE_ERROR });
    const delegateStagingCookie = await delegateSign(minimal, { cookie, origin: STAGING });
    expect(delegateStagingCookie.status).toBe(403);
    const delegateOauth = await delegateSign(minimal, { authorization: 'Bearer unknown-oauth', origin: FOREIGN });
    expect(await delegateOauth.json()).not.toMatchObject({ error: GATE_ERROR });

    // With no credentials at all the gate must not pre-empt the audited
    // missing_authorization denial, whatever the origin.
    const anonForeign = await delegateSign(minimal, { origin: FOREIGN });
    expect(anonForeign.status).toBe(401);
    expect(await anonForeign.json()).toMatchObject({ code: 'missing_authorization' });

    // Device-authorization approve: same cookie-session boundary.
    const approve = (headers: Record<string, string>) =>
      post('/api/device-authorizations/tx_missing/approve', {}, headers);
    expect((await approve({ cookie, origin: SIBLING })).status).toBe(403);
    expect((await approve({ cookie })).status).toBe(403);
    const approveOk = await approve({ cookie, origin: OPENKEY });
    expect(await approveOk.json()).not.toMatchObject({ error: GATE_ERROR });

    await prisma.$disconnect();
  }, 110_000);
}
