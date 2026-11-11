import { createEscrowTestDatabase } from './escrow-test-pg';
import { expect, test } from 'bun:test';
import { Client } from 'pg';
import { PrismaClient } from '@openkey/db';
import { PrismaPg } from '@prisma/adapter-pg';
import { readFileSync } from 'node:fs';
import { createHash, randomBytes, webcrypto } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { seal, deriveNostrPubkey } from '@openkey/tee';
import { mockModules } from './mock-module';
import { createEscrowRouter } from '../routes/escrow';
const run = process.env.OPENKEY_ESCROW_TEST_PG === '1' ? test : test.skip;
run('real HTTP preflight and export bind the same private snapshot and require two approvals', async () => {
  const keys = await Promise.all([0, 1, 2, 3, 4].map(() => webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])));
  const publicKeys = await Promise.all(keys.map(async key => Buffer.from(await webcrypto.subtle.exportKey('raw', key.publicKey)).toString('base64url')));
  const admins = [0, 1].map(i => ({ id: `admin-${i}`, publicKey: publicKeys[i]! }));
  await mockModules({
    '../services/escrow-admins.json': () => ({ default: admins }),
    '../services/escrow-config.json': () => ({ default: { enabled: true, serviceName: 'api', agentVersion: 'synthetic', holders: [2, 3, 4].map(i => ({ id: `holder-${i}`, publicKey: publicKeys[i]! })) } }),
    '../services/escrow-build.json': () => ({ default: { codeHash: 'f'.repeat(64) } }),
  });
  const { createOpenKeyEscrowService } = await import('../services/escrow-service?service-integration' as string);
  const { escrowPreflightMessage, escrowApprovalMessage } = await import('../services/escrow-approval');
  const fixture = await createEscrowTestDatabase();
  const local = fixture.local;
  const setup = new Client(local); await setup.connect();
  const queries: string[] = [];
  const prisma = new PrismaClient({ adapter: new PrismaPg({ ...local }), log: [{ emit: 'event', level: 'query' }] });
  prisma.$on('query', event => queries.push(event.query));
  const derive = (path: string) => new Uint8Array(createHash('sha256').update('SYNTHETIC-ONLY:' + path).digest());
  let derivations = 0;
  const runtimeKeyBuffers: Uint8Array[] = [];
  const runtime = {
    getRuntimeInfo: async () => ({}),
    isInTee: async () => true,
    measurement: async () => ({ appId: 'a'.repeat(40), imageDigest: 'sha256:' + 'b'.repeat(64), composeHash: 'c'.repeat(64), codeHash: 'f'.repeat(64), osVersion: 'synthetic', agentVersion: 'synthetic', bootReference: 'synthetic-boot' }),
    derivePath: async (path: string) => { derivations++; const raw = derive(path); runtimeKeyBuffers.push(raw); const publicKey = privateKeyToAccount(('0x' + Buffer.from(raw).toString('hex')) as `0x${string}`).publicKey; return { key: raw, derivedPublicKey: (parseInt(publicKey.slice(-2), 16) % 2 ? '03' : '02') + publicKey.slice(4, 68), sourcePublicKey: publicKey, signatureChain: ['0'.repeat(130), '0'.repeat(130)] }; },
    getExportQuote: async (headerHash: string) => ({ quote: 'synthetic-quote', eventLog: '[]', reportDataSha256: headerHash }),
  };
  try {
    await setup.query('CREATE TABLE ethereum_keys (id text PRIMARY KEY, "userId" text, "sealingContext" text, "keyType" text, "sealedBlob" text, address text, "publicKey" text NOT NULL DEFAULT \'\', "isCanonicalTinyCloud" boolean NOT NULL DEFAULT false, "keyIndex" integer NOT NULL DEFAULT 0, label text, "archivedAt" timestamptz, "createdAt" timestamptz NOT NULL DEFAULT now())');
    await setup.query('CREATE TABLE nostr_keys (id text PRIMARY KEY, "userId" text, "sealingContext" text, "sealedSecret" text, "pubkeyHex" text, npub text NOT NULL DEFAULT \'\', label text, "revokedAt" timestamptz, "createdAt" timestamptz NOT NULL DEFAULT now())');
    await setup.query('CREATE TABLE user_encryption_key (id text PRIMARY KEY, "userId" text, "sealedPrivateKey" text, "publicKey" text, "createdAt" timestamptz NOT NULL DEFAULT now())');
    for (const name of ['authorization', 'preflight', 'archive']) await setup.query(readFileSync(new URL(`../../../../packages/db/prisma/migrations/20261111_escrow_${name}/migration.sql`, import.meta.url), 'utf8'));
    const privateKey = ('0x' + '01'.padStart(64, '0')) as `0x${string}`;
    const owner = 'PRIVATE_OWNER_ETH'; const rowId = 'PRIVATE_ROW_ETH';
    const address = privateKeyToAccount(privateKey).address;
    await setup.query('INSERT INTO ethereum_keys (id,"userId","keyType","sealedBlob",address) VALUES ($1,$2,$3,$4,$5)', [rowId, owner, 'MANAGED', await seal(privateKey, derive(`openkey/user/${owner}/keys`)), address]);
    let databaseCalls = 0;
    const observed = new Proxy(prisma, { get(target, property) {
      const value = Reflect.get(target, property);
      if (['$transaction', '$queryRawUnsafe', '$executeRawUnsafe'].includes(String(property))) return (...args: unknown[]) => { databaseCalls++; return Reflect.apply(value, target, args); };
      return value;
    } });
    const service = createOpenKeyEscrowService(observed, async () => runtime);
    const router = createEscrowRouter(service);
    const post = (path: string, body: unknown) => router.request(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    expect((await post('/preflight', { approval: {}, approverId: 'admin-1' })).status).toBe(403);
    expect(derivations).toBe(0);
    expect(databaseCalls).toBe(0);
    const descriptor = { measuredConfigHash: service.measuredConfigHash, nonce: randomBytes(32).toString('base64url'), expiresAt: new Date(Date.now() + 600000).toISOString(), adminId: 'admin-0' };
    const signature = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys[0]!.privateKey, escrowPreflightMessage(descriptor))).toString('base64url');
    const response = await post('/preflight', { approval: { ...descriptor, signature }, approverId: 'admin-1' });
    expect(response.status).toBe(200);
    const firstLock = queries.findIndex(query => query.startsWith('LOCK TABLE public.\"ethereum_keys\"'));
    expect(firstLock).toBeGreaterThanOrEqual(0);
    expect(queries[firstLock + 1]).toBe('SET LOCAL search_path = pg_catalog, public');
    expect(queries[firstLock + 2]).toMatch(/^LOCK TABLE public.\"escrow_authorization\"/);
    expect(queries.slice(0, firstLock).every(query => /^(BEGIN|SET TRANSACTION)/i.test(query))).toBe(true);
    const preflight = await response.json();
    const publicText = JSON.stringify(preflight);
    for (const hidden of [owner, rowId, address, 'openkey/user/']) expect(publicText).not.toContain(hidden);
    expect(preflight.summary.totalRows).toBe(1);
    const approval = preflight.approvalDescriptor;
    const signatures = await Promise.all([0, 1].map(async i => ({ id: `admin-${i}`, signature: Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys[i]!.privateKey, escrowApprovalMessage(approval))).toString('base64url') })));
    expect((await post('/export', { approval: { ...approval, signatures: [signatures[0]] } })).status).toBe(403);
    expect((await post('/export', { approval: { ...approval, signatures }, policy: { paths: [] } })).status).toBe(403);
    const secondDescriptor = { ...descriptor, nonce: randomBytes(32).toString('base64url') };
    const secondSignature = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys[0]!.privateKey, escrowPreflightMessage(secondDescriptor))).toString('base64url');
    const secondResponse = await post('/preflight', { approval: { ...secondDescriptor, signature: secondSignature }, approverId: 'admin-1' });
    expect(secondResponse.status).toBe(200);
    const second = await secondResponse.json();
    const beforeWrongPolicy = derivations;
    const beforeWrongPolicyDatabase = databaseCalls;
    expect((await post('/export', { approval: { ...approval, policyHash: second.policyHash, signatures } })).status).toBe(403);
    expect(derivations).toBe(beforeWrongPolicy);
    expect(databaseCalls).toBe(beforeWrongPolicyDatabase);
    const exported = await post('/export', { approval: { ...approval, signatures } });
    expect(exported.status).toBe(200);
    const result = await exported.json();
    expect(result.bundle.header.operatorId).toBe('admin-0');
    expect(result.bundle.header.approverId).toBe('admin-1');
    expect(result.bundle.header.recordManifestHash).toBe(preflight.recordManifestHash);
    expect(result.bundle.header.dbSnapshotHash).toBe(preflight.dbSnapshotHash);
    expect(result.bundle.items.length).toBe(1);
    expect(JSON.stringify(result)).not.toContain(privateKey);
    expect(result.recordManifestUtf8).toBeUndefined();
    expect((await post('/export', { approval: { ...approval, signatures } })).status).toBe(403);
    expect((await setup.query('SELECT count(*)::int AS n FROM escrow_archive')).rows[0]!.n).toBe(1);
    expect((await setup.query('SELECT payload IS NULL AS erased FROM escrow_preflight WHERE "policyHash"=$1', [approval.policyHash])).rows[0]!.erased).toBe(true);
    await setup.query('UPDATE ethereum_keys SET label=$1 WHERE id=$2', ['changed-after-preflight', rowId]);
    const secondApproval = second.approvalDescriptor;
    const secondSignatures = await Promise.all([0, 1].map(async i => ({ id: `admin-${i}`, signature: Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys[i]!.privateKey, escrowApprovalMessage(secondApproval))).toString('base64url') })));
    const refused = await post('/export', { approval: { ...secondApproval, signatures: secondSignatures } });
    expect(refused.status).toBe(403);
    expect(await refused.json()).toEqual({ error: 'escrow_refused' });
    expect((await setup.query('SELECT count(*)::int AS n FROM escrow_archive')).rows[0]!.n).toBe(1);
    expect(runtimeKeyBuffers.every(key => key.every(byte => byte === 0))).toBe(true);
    const failedClaim = (await setup.query('SELECT "consumedAt",payload FROM escrow_preflight WHERE "policyHash"=$1', [second.policyHash])).rows[0]!;
    expect(failedClaim.consumedAt).toBe(null);
    expect(failedClaim.payload).not.toBe(null);
    expect((await setup.query('SELECT count(*)::int AS n FROM escrow_authorization WHERE nonce=$1', [secondApproval.nonce])).rows[0]!.n).toBe(0);
    await setup.query('UPDATE ethereum_keys SET label=NULL WHERE id=$1', [rowId]);
    const retried = await post('/export', { approval: { ...secondApproval, signatures: secondSignatures } });
    expect(retried.status).toBe(200);
    const retriedResult = await retried.json();
    const pending = [];
    for (let i = 0; i < 2; i++) {
      const trigger = { ...descriptor, nonce: randomBytes(32).toString('base64url') };
      const triggerSig = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys[0]!.privateKey, escrowPreflightMessage(trigger))).toString('base64url');
      const pre = await post('/preflight', { approval: { ...trigger, signature: triggerSig }, approverId: 'admin-1' });
      expect(pre.status).toBe(200);
      const desc = (await pre.json()).approvalDescriptor;
      const signed = await Promise.all([0, 1].map(async i => ({ id: `admin-${i}`, signature: Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys[i]!.privateKey, escrowApprovalMessage(desc))).toString('base64url') })));
      pending.push({ approval: { ...desc, signatures: signed } });
    }
    const parallel = await Promise.all(pending.map(body => post('/export', body)));
    expect(parallel.map(response => response.status)).toEqual([200, 200]);
    const newest = await Promise.all(parallel.map(response => response.json()));
    const archives = (await setup.query('SELECT "escrowId" FROM escrow_archive')).rows.map(row => row.escrowId).sort();
    expect(archives).toEqual(newest.map(result => result.archiveId).sort());
    expect(archives).not.toContain(result.archiveId);
    expect(archives).not.toContain(retriedResult.archiveId);
    expect((await setup.query('SELECT count(*)::int AS n FROM escrow_authorization WHERE kind=\'export\'')).rows[0]!.n).toBe(4);
    const script = `import { createOpenKeyEscrowService } from ${JSON.stringify(new URL('../services/escrow-service.ts', import.meta.url).pathname)}; import { createEscrowRouter } from ${JSON.stringify(new URL('../routes/escrow.ts', import.meta.url).pathname)}; const bad=()=>{throw Error('must not query')}; const service=createOpenKeyEscrowService({$transaction:bad,$queryRawUnsafe:bad,$executeRawUnsafe:bad},bad); const response=await createEscrowRouter(service).request('/preflight',{method:'POST',body:'{}'}); if(response.status!==404) process.exit(2);`;
    const child = Bun.spawn([process.execPath, '-e', script], { env: {}, stdout: 'pipe', stderr: 'pipe' });
    expect(await child.exited).toBe(0);

  } finally { await prisma.$disconnect(); await setup.end(); await fixture.cleanup(); }
}, 30000);
