// scripts/ci-register-resource-server.ts against a real (PGlite) database: the client it
// writes, and that the secret never leaves the script except encrypted to its recipient.

import './tc1777-test-env';
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { constants, generateKeyPairSync, privateDecrypt } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { hashClientSecret } from '../services/resource-server';

const root = resolve(import.meta.dir, '../../../..');
const script = join(root, 'scripts/ci-register-resource-server.ts');
const MCP = 'https://mcp.tinycloud.xyz/mcp';

let directory: string;
const keys = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });

async function freshDatabase() {
  if (directory) await rm(directory, { recursive: true, force: true });
  directory = await mkdtemp('/var/tmp/tc1627-register.');
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
}

beforeAll(freshDatabase, 60_000);
beforeEach(freshDatabase, 60_000);
afterAll(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

async function register(overrides: Record<string, string | undefined> = {}) {
  const env: Record<string, string | undefined> = {
    ...process.env,
    DATABASE_URL: `pglite:${directory}`,
    OPENKEY_DATABASE_SCHEMA: undefined,
    RESOURCE_SERVER_NAME: 'MCP resource server',
    RESOURCE_SERVER_ALLOWED_RESOURCES: MCP,
    RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY: keys.publicKey,
    BETTER_AUTH_URL: 'https://api.openkey.so',
    OAUTH_VALID_AUDIENCES: undefined,
    ...overrides,
  };
  const child = Bun.spawn([process.execPath, script], { cwd: root, env: env as Record<string, string>, stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  return { stdout, stderr, exitCode };
}

async function rows() {
  const database = new PGlite(directory);
  try {
    return (await database.query<Record<string, unknown>>('select * from oauth_client')).rows;
  } finally {
    await database.close();
  }
}

function printed(stdout: string, name: string): string {
  const line = stdout.split('\n').find((entry) => entry.startsWith(`${name}=`));
  if (!line) throw new Error(`no ${name} line in: ${stdout}`);
  return line.slice(name.length + 1);
}

describe('registering a resource server', () => {
  test('writes the confidential client, and the secret is only ever printed encrypted to the recipient', async () => {
    const result = await register();
    expect(result.exitCode, result.stderr).toBe(0);
    const clientId = printed(result.stdout, 'CLIENT_ID');
    expect(clientId).toMatch(/^ok_[0-9a-f]{32}$/);
    expect(printed(result.stdout, 'ALLOWED_RESOURCES')).toBe(MCP);

    const secret = privateDecrypt(
      { key: keys.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(printed(result.stdout, 'SECRET_CIPHERTEXT_RSA_OAEP_SHA256_B64'), 'base64'),
    ).toString('utf8');
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(result.stdout).not.toContain(secret);
    expect(result.stderr).not.toContain(secret);

    const stored = await rows();
    expect(stored).toHaveLength(1);
    const row = stored[0]!;
    expect(row).toMatchObject({
      clientId, name: 'MCP resource server', public: false, type: 'web', disabled: false, skipConsent: false,
      tokenEndpointAuthMethod: 'client_secret_basic', grantTypes: ['authorization_code'], responseTypes: ['code'],
      scopes: ['openid'], redirectUris: ['https://resource-server.invalid/callback'],
      clientSecret: hashClientSecret(secret),
      metadata: { tinycloudResourceServer: { allowedResources: [MCP] } },
    });
    expect(JSON.stringify(row)).not.toContain(secret);
  }, 90_000);

  test('accepts the public key as base64 of the PEM, which a single-line workflow input needs', async () => {
    const result = await register({ RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY: Buffer.from(keys.publicKey).toString('base64') });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(await rows()).toHaveLength(1);
  }, 90_000);

  test('a second run with the same name changes nothing and shows no secret', async () => {
    const first = await register();
    expect(first.exitCode, first.stderr).toBe(0);
    const second = await register();
    expect(second.exitCode, second.stderr).toBe(0);
    expect(printed(second.stdout, 'CLIENT_ID')).toBe(printed(first.stdout, 'CLIENT_ID'));
    expect(second.stdout).not.toContain('SECRET_CIPHERTEXT');
    expect(await rows()).toHaveLength(1);
  }, 120_000);

  test.each([
    ['an audience the server does not issue tokens for', { RESOURCE_SERVER_ALLOWED_RESOURCES: 'https://other.example/mcp' }, /not an audience/],
    ['a resource URL that is not canonical', { RESOURCE_SERVER_ALLOWED_RESOURCES: 'https://mcp.tinycloud.xyz' }, /not a canonical https resource URL/],
    ['no resources', { RESOURCE_SERVER_ALLOWED_RESOURCES: ' , ' }, /at least one allowed resource is required/],
    ['no name', { RESOURCE_SERVER_NAME: '' }, /RESOURCE_SERVER_NAME is required/],
    ['no recipient key', { RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY: '' }, /RECIPIENT_PUBLIC_KEY is required/],
    ['a recipient value that is not a key', { RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY: 'not a key' }, /is not a public key/],
    ['a weak RSA key', { RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY: generateKeyPairSync('rsa', { modulusLength: 1024, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey }, /at least 2048 bits/],
    ['a private key in place of the public key', { RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY: keys.privateKey }, /must be a public key/],
    ['a base64 private key in place of the public key', { RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY: Buffer.from(keys.privateKey).toString('base64') }, /must be a public key/],
    ['an EC key', { RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY: generateKeyPairSync('ec', { namedCurve: 'P-256', publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey }, /must be an RSA key/],
  ] as Array<[string, Record<string, string>, RegExp]>)('%s is refused and writes nothing', async (_name, overrides, message) => {
    const result = await register(overrides);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toMatch(message);
    expect(result.stdout).not.toContain('SECRET_CIPHERTEXT');
    expect(await rows()).toHaveLength(0);
  }, 90_000);

  test('an extra audience the API is configured with can be registered', async () => {
    const result = await register({ RESOURCE_SERVER_ALLOWED_RESOURCES: 'https://other.example/mcp', OAUTH_VALID_AUDIENCES: 'https://other.example/mcp' });
    expect(result.exitCode, result.stderr).toBe(0);
  }, 90_000);
});
