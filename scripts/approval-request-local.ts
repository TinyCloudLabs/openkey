#!/usr/bin/env bun
// Local TC-2212 proof only: actual auth, managed signing, Hono routes and Prisma.
// No mocked approval response or external account. Run db:push into this private
// directory first, then start the existing web app against this API.
import { randomBytes, randomUUID } from 'node:crypto';
import { writeFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { serializeSignedCookie } from 'better-call';

const directory = process.env.TC2212_RUNTIME_DIR;
if (!directory || !/^\/var\/tmp\/TC2212[^/]*$/.test(directory) || (await stat(directory)).mode & 0o077) {
  throw new Error('TC2212_RUNTIME_DIR must be an owned private mktemp directory under /var/tmp');
}
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl || databaseUrl !== `pglite:${join(directory, 'db')}`) throw new Error('Use only this runner\'s private PGlite database');
if (!process.env.BETTER_AUTH_URL || !process.env.WEBAUTHN_ORIGIN || !process.env.APPROVAL_OPENKEY_ORIGIN || !process.env.API_PORT) {
  throw new Error('Set explicit local API/web origins and API_PORT');
}
if (!['localhost', '127.0.0.1'].includes(new URL(process.env.BETTER_AUTH_URL).hostname) || !['localhost', '127.0.0.1'].includes(new URL(process.env.WEBAUTHN_ORIGIN).hostname)) {
  throw new Error('Local synthetic runner refuses non-loopback account origins');
}
process.env.NODE_ENV = 'test';
process.env.TEE_MODE = 'development';
process.env.BETTER_AUTH_SECRET = randomBytes(48).toString('base64url');
process.env.WEBAUTHN_RP_ID = new URL(process.env.WEBAUTHN_ORIGIN).hostname;
process.env.CORS_ORIGIN = process.env.WEBAUTHN_ORIGIN;
process.env.APPROVAL_RESULT_RETENTION_SECONDS = '600';
process.env.RESEND_API_KEY = '';
process.env.GOOGLE_CLIENT_ID = '';
process.env.GOOGLE_CLIENT_SECRET = '';
process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';

// These modules capture auth/database/TEE environment at import time. Import
// only after the private-runtime checks and synthetic environment are installed.
const { createPrismaClient } = await import('@openkey/db');
const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
const prisma = createPrismaClient();
const userId = `tc2212-${randomUUID()}`;
await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: 'Synthetic CLI Owner', emailVerified: true } });
const privateKey = generatePrivateKey();
const address = getAddressFromPrivateKey(privateKey);
const sealingContext = randomBytes(32).toString('base64url');
const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
const key = await prisma.ethereumKey.create({ data: { userId, address, publicKey: '0x1', sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
const sessionToken = randomBytes(32).toString('base64url');
await prisma.session.create({ data: { id: randomUUID(), token: sessionToken, userId, expiresAt: new Date(Date.now() + 3600_000) } });
const { auth } = await import('../apps/api/src/auth');
const context = await auth.$context;
const cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
await writeFile(join(directory, 'owner-session.json'), JSON.stringify({ cookie, keyId: key.id, address, ownerDid: `did:pkh:eip155:1:${address}`, apiOrigin: process.env.BETTER_AUTH_URL, webOrigin: process.env.WEBAUTHN_ORIGIN }), { mode: 0o600 });
const app = (await import('../apps/api/src/index')).default;
const server = Bun.serve({ hostname: '127.0.0.1', port: Number(process.env.API_PORT), fetch: app.fetch });
console.log(`TC2212_SYNTHETIC_API_READY port=${server.port} sessionFile=${resolve(directory, 'owner-session.json')}`);
