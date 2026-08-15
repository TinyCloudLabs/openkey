#!/usr/bin/env bun

/**
 * Runs the public CLI against a real candidate OpenKey API.  The approving
 * browser identity is a real Better Auth development OTP session; only the
 * TinyCloud Node/registry service is a local fixture.
 */
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createCipheriv, createHmac, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import { completeSessionSetup, makeSpaceId, prepareSession } from '@tinycloud/node-sdk-wasm';
import { CAPABILITIES } from '@tinycloud/bootstrap';
import { deviceAuthorizationDescriptorDigest, type DeviceAuthorizationRecord } from '../apps/api/src/services/device-authorization';
import { createPrismaClient } from '@openkey/db';

const [api, ...args] = process.argv.slice(2);
const flag = args.indexOf('--cli');
if (!api || flag < 0 || !args[flag + 1]) throw new Error('Usage: bun scripts/candidate-device-authorization-smoke.ts API_URL --cli CLI_PATH');
const cliPath = isAbsolute(args[flag + 1]!) ? args[flag + 1]! : resolve(args[flag + 1]!);
const nodeExecutable = Bun.which('node') ?? 'node';
const email = 'test@openkey.dev';
const database = createPrismaClient();

type Lookup = DeviceAuthorizationRecord & { descriptor: unknown; descriptorDigest: string };
let approvedSessionDid = '';
let uploadCount = 0;
const server = Bun.serve({
  port: 0,
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === 'POST' && url.pathname === '/delegate') return Response.json({ activated: ['applications'], skipped: [] });
    if (request.method === 'POST' && url.pathname === '/share/upload/attestation') {
      const body = await request.json() as Record<string, unknown>;
      const now = new Date();
      return Response.json({ type: 'TinyCloudShareUploadAttestation', version: 1, issuer: 'did:web:node.smoke.invalid', kid: 'did:web:node.smoke.invalid#share-upload', ownerDid: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111', sessionDid: approvedSessionDid, shareOrigin: 'https://share.tinycloud.xyz', encryptedBlobCid: body.encryptedBlobCid, encryptedBlobSha256: body.encryptedBlobSha256, byteLength: body.byteLength, deleteAfter: body.deleteAfter, retention: 'until-delete', issuedAt: now.toISOString(), authorityExpiresAt: new Date(now.getTime() + 120_000).toISOString(), expiresAt: new Date(now.getTime() + 60_000).toISOString(), jti: randomBytes(18).toString('base64url'), signature: randomBytes(64).toString('base64url') });
    }
    if (request.method === 'POST' && url.pathname === '/registry/blobs') {
      if (!request.headers.get('x-tinycloud-upload-attestation')) return Response.json({ error: 'missing_attestation' }, { status: 401 });
      uploadCount += 1;
      const attestation = JSON.parse(request.headers.get('x-tinycloud-upload-attestation')!) as { encryptedBlobCid: string; deleteAfter: string };
      return Response.json({ cid: attestation.encryptedBlobCid, deleteAfter: attestation.deleteAfter });
    }
    return new Response('not found', { status: 404 });
  },
});
const nodeOrigin = `http://127.0.0.1:${server.port}`;

async function sessionToken() {
  const send = await fetch(`${api}/api/auth/email-otp/send-verification-otp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, type: 'sign-in' }) });
  if (!send.ok) throw new Error(`OTP request failed: ${send.status}`);
  const verify = await fetch(`${api}/api/auth/sign-in/email-otp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, otp: '000000' }) });
  const body = await verify.json() as { token?: string; user?: { id?: string } };
  const token = verify.headers.get('set-auth-token');
  if (!verify.ok || !body.token || !body.user?.id || !token) throw new Error(`OTP session failed: ${verify.status}`);
  return token;
}

function relay(record: Lookup, delegation: Record<string, unknown>) {
  const ephemeral = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const secret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: createPublicKey({ key: record.relayPublicJwk, format: 'jwk' }) });
  const extracted = createHmac('sha256', Buffer.from(record.id)).update(secret).digest();
  const key = createHmac('sha256', extracted).update(Buffer.from('openkey-device-relay-v1')).update(Buffer.from([1])).digest();
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(Buffer.from(record.id));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(delegation)), cipher.final(), cipher.getAuthTag()]);
  return { relay: { version: 1, algorithm: 'ECDH-P256-A256GCM', ephemeralPublicJwk: ephemeral.publicKey.export({ format: 'jwk' }), nonce: nonce.toString('base64url'), ciphertext: ciphertext.toString('base64url') }, binding: { transactionId: record.id, sessionDid: record.sessionDid, nodeOrigin: record.nodeOrigin, shareOrigin: record.shareOrigin, permissions: record.permissions, descriptorDigest: deviceAuthorizationDescriptorDigest(record), delegationExpiresAt: String(delegation.expiresAt) } };
}

async function delegation(record: Lookup) {
  const account = privateKeyToAccount(`0x${randomBytes(32).toString('hex')}`);
  const expirationTime = new Date(Math.min(new Date(record.delegationExpiresAt).getTime(), Date.now() + 30 * 24 * 60 * 60 * 1000 - 1000)).toISOString();
  const spaceId = makeSpaceId(account.address, 1, 'applications');
  const prepared = prepareSession({ address: account.address, chainId: 1, domain: 'cli.tinycloud.xyz', issuedAt: new Date().toISOString(), expirationTime, spaceId, jwk: record.publicJwk as { kty: string; crv: string; x: string }, abilities: { capabilities: { '': [CAPABILITIES.READ] } } });
  const signature = await account.signMessage({ message: prepared.siwe });
  const session = completeSessionSetup({ ...prepared, signature });
  approvedSessionDid = record.sessionDid;
  return { ...session, jwk: record.publicJwk, ownerDid: `did:pkh:eip155:1:${account.address}`, address: account.address, chainId: 1, siwe: prepared.siwe, signature, expiresAt: expirationTime, expirationTime, expiry: expirationTime, permissions: [{ service: 'capabilities', space: spaceId, path: '', actions: [CAPABILITIES.READ] }], deviceBinding: { transactionId: record.id, sessionDid: record.sessionDid, nodeOrigin: record.nodeOrigin, shareOrigin: record.shareOrigin, permissions: record.permissions, descriptorDigest: deviceAuthorizationDescriptorDigest(record) } };
}

async function waitFor<T>(name: string, predicate: () => Promise<T | null>, timeoutMs = 30_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) { const value = await predicate(); if (value) return value; await Bun.sleep(100); }
  throw new Error(`timed out waiting for ${name}`);
}

const root = await mkdtemp(join(tmpdir(), 'tc-candidate-device-auth-'));
let child: ReturnType<typeof Bun.spawn> | undefined;
try {
  await writeFile(join(root, 'report.md'), '# Candidate device authorization smoke\n');
  const token = await sessionToken();
  child = Bun.spawn([nodeExecutable, cliPath, 'share', 'publish', 'report.md', '--registry', `${nodeOrigin}/registry`, '--insecure-registry'], { cwd: root, env: { ...process.env, TC_HOME: root, TC_OPENKEY_HOST: api, TC_HOST: nodeOrigin, TC_AUTH_NO_POPUP: '1' }, stdout: 'pipe', stderr: 'pipe' });
  const stderrPromise = new Response(child.stderr).text();
  const stdoutPromise = new Response(child.stdout).text();
  const record = await waitFor('CLI transaction', async () => {
    // The API deliberately has no enumeration endpoint. The candidate database is
    // inspected only to discover the opaque transaction created by the CLI; the
    // public lookup, authenticated approval, and one-time token consumption stay HTTP.
    const result = await database.deviceAuthorization.findFirst({ where: { status: 'PENDING', nodeOrigin }, orderBy: { requestedAt: 'desc' } });
    return result as Lookup | null;
  });
  const lookupResponse = await fetch(`${api}/api/device-authorizations/lookup?user_code=${encodeURIComponent(record.userCode)}`);
  const lookup = await lookupResponse.json() as Lookup;
  if (!lookupResponse.ok || lookup.id !== record.id || lookup.descriptorDigest !== deviceAuthorizationDescriptorDigest(record)) {
    throw new Error('public device lookup did not return the server-owned descriptor');
  }
  const approved = await fetch(`${api}/api/device-authorizations/${record.id}/approve`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify(relay(lookup, await delegation(lookup))) });
  if (!approved.ok || (await approved.json() as { approved?: boolean }).approved !== true) throw new Error(`authenticated approval failed: ${approved.status}`);
  const [stdout, stderr, exitCode] = await Promise.all([stdoutPromise, stderrPromise, child.exited]);
  if (exitCode !== 0) throw new Error(`CLI exited ${exitCode}: ${stderr}`);
  const result = stdout.trim();
  if (!/^https:\/\/share\.tinycloud\.xyz\/s\/[A-Za-z0-9_-]+#k=/.test(result) || uploadCount !== 2) throw new Error('CLI did not complete the one-shot Share upload');
  const profile = JSON.parse(await readFile(join(root, '.tinycloud/profiles/default/profile.json'), 'utf8'));
  if (profile.authMethod !== 'openkey') throw new Error('CLI did not persist the authenticated device delegation');
  process.stdout.write(JSON.stringify({ publicCliProcess: true, apiTransactionStart: true, renderedDescriptor: true, authenticatedApproval: true, descriptorBoundConsumption: true, shareAuthorityVerified: true, oneShotUpload: true, finalShareUrl: true }) + '\n');
} finally {
  child?.kill(9); server.stop(true); await database.$disconnect(); await rm(root, { recursive: true, force: true });
}
