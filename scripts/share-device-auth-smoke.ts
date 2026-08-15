import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createCipheriv, createHmac, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import { chromium } from 'playwright';
import { completeSessionSetup, makeSpaceId, prepareSession } from '@tinycloud/node-sdk-wasm';
import { CAPABILITIES } from '@tinycloud/bootstrap';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  deviceAuthorizationDescriptorDigest,
  type DeviceAuthorizationRecord,
} from '../apps/api/src/services/device-authorization';

const cliFlag = process.argv.indexOf('--cli');
if (cliFlag < 0 || !process.argv[cliFlag + 1]) {
  throw new Error('Usage: bun scripts/share-device-auth-smoke.ts --cli /absolute/path/to/packages/cli/dist/index.js');
}
const cliPath = isAbsolute(process.argv[cliFlag + 1]!)
  ? process.argv[cliFlag + 1]!
  : resolve(process.cwd(), process.argv[cliFlag + 1]!);
const nodeExecutable = Bun.which('node') ?? 'node';

const store = new MemoryDeviceAuthorizationStore();
let service: DeviceAuthorizationService;
let approvedSessionDid = '';
let uploadCount = 0;
let retainedForSevenDays = true;
const requestPaths: string[] = [];
let createdRecord: DeviceAuthorizationRecord | null = null;

async function createApprovedDelegation(record: DeviceAuthorizationRecord) {
  const account = privateKeyToAccount(`0x${randomBytes(32).toString('hex')}`);
  const expirationTime = new Date(Math.min(
    record.delegationExpiresAt.getTime(),
    Date.now() + 30 * 24 * 60 * 60 * 1000 - 1000,
  )).toISOString();
  const spaceId = makeSpaceId(account.address, 1, 'applications');
  const prepared = prepareSession({
    address: account.address,
    chainId: 1,
    domain: 'cli.tinycloud.xyz',
    issuedAt: new Date().toISOString(),
    expirationTime,
    spaceId,
    jwk: record.publicJwk as { kty: string; crv: string; x: string },
    abilities: { capabilities: { '': [CAPABILITIES.READ] } },
  });
  const signature = await account.signMessage({ message: prepared.siwe });
  const session = completeSessionSetup({ ...prepared, signature });
  approvedSessionDid = record.sessionDid;
  return {
    ...session,
    jwk: record.publicJwk,
    ownerDid: `did:pkh:eip155:1:${account.address}`,
    address: account.address,
    chainId: 1,
    siwe: prepared.siwe,
    signature,
    expiresAt: expirationTime,
    expirationTime,
    expiry: expirationTime,
    permissions: [{
      service: 'capabilities',
      space: spaceId,
      path: '',
      actions: [CAPABILITIES.READ],
    }],
    deviceBinding: {
      transactionId: record.id,
      sessionDid: record.sessionDid,
      nodeOrigin: record.nodeOrigin,
      shareOrigin: record.shareOrigin,
      permissions: record.permissions,
      descriptorDigest: deviceAuthorizationDescriptorDigest(record),
    },
  };
}

function encryptApprovedDelegation(record: DeviceAuthorizationRecord, delegation: Record<string, unknown>) {
  const ephemeral = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const sharedSecret = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: createPublicKey({ key: record.relayPublicJwk, format: 'jwk' }),
  });
  const extracted = createHmac('sha256', Buffer.from(record.id)).update(sharedSecret).digest();
  const key = createHmac('sha256', extracted)
    .update(Buffer.from('openkey-device-relay-v1'))
    .update(Buffer.from([1]))
    .digest();
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(record.id));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(delegation)),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return {
    relay: {
      version: 1,
      algorithm: 'ECDH-P256-A256GCM',
      ephemeralPublicJwk: ephemeral.publicKey.export({ format: 'jwk' }),
      nonce: nonce.toString('base64url'),
      ciphertext: ciphertext.toString('base64url'),
    },
    binding: {
      transactionId: record.id,
      sessionDid: record.sessionDid,
      nodeOrigin: record.nodeOrigin,
      shareOrigin: record.shareOrigin,
      permissions: record.permissions,
      descriptorDigest: deviceAuthorizationDescriptorDigest(record),
      delegationExpiresAt: String(delegation.expiresAt),
    },
  };
}

const server = Bun.serve({
  port: 0,
  async fetch(request) {
    const url = new URL(request.url);
    requestPaths.push(`${request.method} ${url.pathname}`);
    if (request.method === 'POST' && url.pathname === '/api/device-authorizations') {
      const started = await service.start(await request.json(), '127.0.0.1');
      const record = await store.findById(started.transactionId);
      if (!record) return Response.json({ error: 'missing_transaction' }, { status: 500 });
      createdRecord = record;
      return Response.json(started, { status: 201 });
    }
    if (request.method === 'GET' && url.pathname === '/api/device-authorizations/lookup') {
      const lookup = await service.lookup(url.searchParams.get('user_code') ?? '');
      if (!lookup) return Response.json({ error: 'not_found' }, { status: 404, headers: corsHeaders() });
      createdRecord = await store.findById(lookup.id);
      return Response.json({
        ...lookup,
        delegationExpiresAt: lookup.delegationExpiresAt.toISOString(),
        transactionExpiresAt: lookup.transactionExpiresAt.toISOString(),
        requestedAt: lookup.requestedAt.toISOString(),
        nextPollAt: lookup.nextPollAt.toISOString(),
      }, { headers: corsHeaders() });
    }
    if (request.method === 'POST' && url.pathname === '/api/device-authorizations/token') {
      try {
        return Response.json(await service.poll(await request.json()));
      } catch (error) {
        const typed = error as { code?: string; message?: string; status?: number };
        return Response.json({ error: typed.code, errorDescription: typed.message }, { status: typed.status ?? 500 });
      }
    }
    if (request.method === 'POST' && url.pathname === '/delegate') {
      return Response.json({ activated: ['applications'], skipped: [] });
    }
    if (request.method === 'POST' && url.pathname === '/share/upload/attestation') {
      const body = await request.json() as Record<string, unknown>;
      const issuedAt = new Date();
      return Response.json({
        type: 'TinyCloudShareUploadAttestation',
        version: 1,
        issuer: 'did:web:node.smoke.invalid',
        kid: 'did:web:node.smoke.invalid#share-upload',
        ownerDid: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111',
        sessionDid: approvedSessionDid,
        shareOrigin: 'https://share.tinycloud.xyz',
        encryptedBlobCid: body.encryptedBlobCid,
        encryptedBlobSha256: body.encryptedBlobSha256,
        byteLength: body.byteLength,
        deleteAfter: body.deleteAfter,
        retention: 'until-delete',
        issuedAt: issuedAt.toISOString(),
        authorityExpiresAt: new Date(issuedAt.getTime() + 120_000).toISOString(),
        expiresAt: new Date(issuedAt.getTime() + 60_000).toISOString(),
        jti: randomBytes(18).toString('base64url'),
        signature: randomBytes(64).toString('base64url'),
      });
    }
    if (request.method === 'POST' && url.pathname === '/registry/blobs') {
      const encoded = request.headers.get('x-tinycloud-upload-attestation');
      if (!encoded) return Response.json({ error: 'missing_attestation' }, { status: 401 });
      const attestation = JSON.parse(encoded) as { encryptedBlobCid: string; deleteAfter: string };
      const remaining = Date.parse(attestation.deleteAfter) - Date.now();
      retainedForSevenDays &&= remaining > 6.9 * 24 * 60 * 60 * 1000 && remaining <= 7.01 * 24 * 60 * 60 * 1000;
      uploadCount += 1;
      return Response.json({ cid: attestation.encryptedBlobCid, deleteAfter: attestation.deleteAfter });
    }
    return new Response('not found', { status: 404 });
  },
});

function corsHeaders() {
  return { 'access-control-allow-origin': '*' };
}

async function waitFor<T>(description: string, predicate: () => T | null | undefined | Promise<T | null | undefined>, timeoutMs = 30_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await Bun.sleep(50);
  }
  throw new Error(`timed out waiting for ${description}`);
}

const origin = `http://127.0.0.1:${server.port}`;
service = new DeviceAuthorizationService(store, {
  verificationOrigin: origin,
  encryptionSecret: 'share-device-auth-public-smoke-secret-only',
});

const root = await mkdtemp(join(tmpdir(), 'tc-share-device-auth-smoke-'));
let vite: ReturnType<typeof Bun.spawn> | undefined;
let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
try {
  const report = join(root, 'report.md');
  await writeFile(report, '# Share-first device auth smoke\n', 'utf8');
  const webPort = 5788;
  vite = Bun.spawn(['bun', join(import.meta.dir, '..', 'node_modules', 'vite', 'bin', 'vite.js'), '--port', `${webPort}`, '--strictPort'], {
    cwd: join(import.meta.dir, '..', 'apps', 'web'),
    env: { ...process.env, VITE_API_URL: origin },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  await waitFor('the local OpenKey device page', () => fetch(`http://127.0.0.1:${webPort}/device`)
    .then((response) => response.ok ? true : null)
    .catch(() => null), 60_000);
  const command = [
    nodeExecutable,
    cliPath,
    'share',
    'publish',
    report,
    '--registry',
    `${origin}/registry`,
    '--insecure-registry',
  ];
  const child = Bun.spawn(command, {
    cwd: root,
    env: {
      ...process.env,
      TC_HOME: root,
      TC_OPENKEY_HOST: origin,
      TC_HOST: origin,
      TC_AUTH_NO_POPUP: '1',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const stdoutPromise = new Response(child.stdout).text();
  const stderrPromise = new Response(child.stderr).text();
  const record = await waitFor('the CLI device transaction', () => createdRecord);
  // The CLI points to the API host. The browser is deliberately pointed at the
  // separately-hosted SvelteKit UI, which performs the real lookup and renders
  // the exact server-owned descriptor before this local fixture approves it.
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${webPort}/device?user_code=${encodeURIComponent(record.userCode)}`);
  await page.getByText('TinyCloud CLI', { exact: true }).waitFor();
  await page.getByText('tinycloud.share.publish.v1', { exact: true }).waitFor();
  await page.getByText('Publish encrypted files through TinyCloud Share using one-shot Node upload attestations.', { exact: true }).waitFor();
  if (!await page.getByText(record.nodeOrigin, { exact: true }).isVisible() || !await page.getByText(record.shareOrigin, { exact: true }).isVisible()) {
    throw new Error('device page did not render the server-owned resource origins');
  }
  const delegation = await createApprovedDelegation(record);
  await service.approve(record.id, 'smoke-passkey-user', encryptApprovedDelegation(record, delegation));
  const [stdout, stderr, exitCode] = await Promise.all([stdoutPromise, stderrPromise, child.exited]);
  const link = stdout.trim();
  if (exitCode !== 0) {
    const files = await readdir(root, { recursive: true });
    throw new Error(`CLI exited ${exitCode}: ${stderr}\nrequests=${requestPaths.join(',')}\nfiles=${files.join(',')}`);
  }
  if (!/^https:\/\/share\.tinycloud\.xyz\/s\/[A-Za-z0-9_-]+#k=/.test(link)) throw new Error(`CLI did not return a complete Share URL: ${link}`);
  if (!/Visit:\s+http:\/\/127\.0\.0\.1:\d+\/device/.test(stderr) || !/Code:\s+[A-Z2-9]{4}-[A-Z2-9]{4}/.test(stderr)) {
    throw new Error(`CLI did not print the device verification URL and code: ${stderr}`);
  }
  if (uploadCount !== 2) throw new Error(`expected content and envelope uploads, received ${uploadCount}`);
  if (!retainedForSevenDays) throw new Error('Share upload retention changed from seven days');
  const profile = JSON.parse(await readFile(join(root, '.tinycloud/profiles/default/profile.json'), 'utf8'));
  const session = JSON.parse(await readFile(join(root, '.tinycloud/profiles/default/session.json'), 'utf8'));
  if (profile.authMethod !== 'openkey' || session.verificationMethod !== approvedSessionDid || typeof session.jwk?.d !== 'string') {
    throw new Error('CLI did not persist the verified delegation with its local private session key');
  }
  process.stdout.write(JSON.stringify({
    command: `tc share publish report.md --registry ${origin}/registry --insecure-registry`,
    result: link,
    devicePrompt: true,
    renderedDescriptor: true,
    delegationPersisted: true,
    uploads: uploadCount,
    retentionDays: 7,
  }) + '\n');
} finally {
  await browser?.close();
  vite?.kill(9);
  server.stop(true);
  await rm(root, { recursive: true, force: true });
}
