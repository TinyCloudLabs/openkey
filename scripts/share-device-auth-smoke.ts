import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import { completeSessionSetup, makeSpaceId, prepareSession } from '@tinycloud/node-sdk-wasm';
import { CAPABILITIES } from '@tinycloud/bootstrap';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  type DeviceAuthorizationRecord,
} from '../apps/api/src/services/device-authorization';

const cliFlag = process.argv.indexOf('--cli');
if (cliFlag < 0 || !process.argv[cliFlag + 1]) {
  throw new Error('Usage: bun scripts/share-device-auth-smoke.ts --cli /absolute/path/to/packages/cli/dist/index.js');
}
const cliPath = isAbsolute(process.argv[cliFlag + 1]!)
  ? process.argv[cliFlag + 1]!
  : resolve(process.cwd(), process.argv[cliFlag + 1]!);

const store = new MemoryDeviceAuthorizationStore();
let service: DeviceAuthorizationService;
let approvedSessionDid = '';
let uploadCount = 0;
let retainedForSevenDays = true;
const requestPaths: string[] = [];

async function createApprovedDelegation(record: DeviceAuthorizationRecord) {
  const account = privateKeyToAccount(`0x${randomBytes(32).toString('hex')}`);
  const expirationTime = record.delegationExpiresAt.toISOString();
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
      await service.approve(record.id, 'smoke-passkey-user', await createApprovedDelegation(record));
      return Response.json(started, { status: 201 });
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

const origin = `http://127.0.0.1:${server.port}`;
service = new DeviceAuthorizationService(store, {
  verificationOrigin: origin,
  encryptionSecret: 'share-device-auth-public-smoke-secret-only',
});

const root = await mkdtemp(join(tmpdir(), 'tc-share-device-auth-smoke-'));
try {
  const report = join(root, 'report.md');
  await writeFile(report, '# Share-first device auth smoke\n', 'utf8');
  const command = [
    process.execPath,
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
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  const link = stdout.trim();
  if (exitCode !== 0) {
    const sdkProbe = Bun.spawn([
      process.execPath,
      '-e',
      `import { ensureAuthenticated } from './packages/cli/src/lib/sdk.ts'; await ensureAuthenticated({profile:'default',host:${JSON.stringify(origin)},verbose:false,noCache:false,quiet:true}); console.log('restore-ok')`,
    ], {
      cwd: resolve(dirname(cliPath), '../../..'),
      env: { ...process.env, TC_HOME: root, TC_HOST: origin },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [probeOut, probeErr] = await Promise.all([new Response(sdkProbe.stdout).text(), new Response(sdkProbe.stderr).text(), sdkProbe.exited]);
    const files = await readdir(root, { recursive: true });
    throw new Error(`CLI exited ${exitCode}: ${stderr}\nrequests=${requestPaths.join(',')}\nfiles=${files.join(',')}\nrestore=${probeOut}${probeErr}`);
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
    delegationPersisted: true,
    uploads: uploadCount,
    retentionDays: 7,
  }) + '\n');
} finally {
  server.stop(true);
  await rm(root, { recursive: true, force: true });
}
