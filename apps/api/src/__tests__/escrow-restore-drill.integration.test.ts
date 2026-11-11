import { escrowTestPostgres } from './escrow-test-pg';
import { expect, test } from 'bun:test';
import { Client } from 'pg';
import { PrismaClient } from '@openkey/db';
import { PrismaPg } from '@prisma/adapter-pg';
import { createHash, generateKeyPairSync, webcrypto, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { seal, unseal, deriveNostrPubkey, prepareEscrowExport, encodeRecordManifest, deriveRecoveryTargetPolicy, EscrowRecoverySessions, wrapRecoveryShare, type ExportPolicy } from '@openkey/tee';
import { unwrapEscrowShare } from '../../../../packages/tee/src/escrow-envelope';
import vector from '../../../../packages/tee/tests/fixtures/escrow-header-v1.json';
import { createPrismaEscrowDatabase } from '../services/escrow-prisma';
import { withFencedOpenKeySnapshot } from '../services/escrow-snapshot';
import { validateOpenKeySnapshot } from '../services/escrow-validate';
import { restoreOpenKeyDrill } from '../services/escrow-restore-drill';

const run = process.env.OPENKEY_ESCROW_TEST_PG === '1' ? test : test.skip;
run('isolated real PostgreSQL drill restores every key type atomically under a new policy', async () => {
  const local = escrowTestPostgres();
  const control = new Client({ ...local, database: 'postgres' }); await control.connect();
  const name = 'tc_' + crypto.randomUUID().replaceAll('-', '') + '_escrow_drill';
  await control.query(`CREATE DATABASE "${name}"`);
  const setup = new Client({ ...local, database: name }); await setup.connect();
  const queries: string[] = [];
  const prisma = new PrismaClient({ adapter: new PrismaPg({ ...local, database: name }), log: [{ emit: 'event', level: 'query' }] });
  prisma.$on('query', event => queries.push(event.query));
  const database = createPrismaEscrowDatabase(prisma);
  const old = (path: string) => new Uint8Array(createHash('sha256').update('SYNTHETIC-OLD:' + path).digest());
  const fresh = (path: string) => new Uint8Array(createHash('sha256').update('SYNTHETIC-NEW:' + path).digest());
  const measurement = { appId: 'a'.repeat(40), composeHash: 'b'.repeat(64), imageDigest: 'sha256:' + 'c'.repeat(64), codeHash: 'd'.repeat(64), bootReference: 'synthetic-drill-boot', osVersion: 'synthetic', agentVersion: 'synthetic' };
  const buffers: Uint8Array[] = [];
  const runtime = { isInTee: async () => true, measurement: async () => measurement, derivePath: async (path: string) => {
    const key = fresh(path); buffers.push(key);
    return { key, derivedPublicKey: Buffer.from(secp256k1.getPublicKey(key, true)).toString('hex'), sourcePublicKey: privateKeyToAccount(('0x' + '03'.padStart(64, '0')) as `0x${string}`).publicKey, signatureChain: ['0'.repeat(130), '0'.repeat(130)] };
  } };
  try {
    await setup.query('CREATE TABLE ethereum_keys (id text PRIMARY KEY, "userId" text, "sealingContext" text, "keyType" text, "sealedBlob" text, address text, "publicKey" text NOT NULL DEFAULT \'\', "isCanonicalTinyCloud" boolean NOT NULL DEFAULT false, "keyIndex" integer NOT NULL DEFAULT 0, label text, "archivedAt" timestamptz, "createdAt" timestamptz NOT NULL DEFAULT now())');
    await setup.query('CREATE TABLE nostr_keys (id text PRIMARY KEY, "userId" text, "sealingContext" text, "sealedSecret" text, "pubkeyHex" text, npub text NOT NULL DEFAULT \'\', label text, "revokedAt" timestamptz, "createdAt" timestamptz NOT NULL DEFAULT now())');
    await setup.query('CREATE TABLE user_encryption_key (id text PRIMARY KEY, "userId" text, "sealedPrivateKey" text, "publicKey" text, "createdAt" timestamptz NOT NULL DEFAULT now())');
    await setup.query(readFileSync(new URL('../../../../packages/db/prisma/migrations/20261111_escrow_restore_receipt/migration.sql', import.meta.url), 'utf8'));
    const ethereumSecret = ('0x' + '01'.padStart(64, '0')) as `0x${string}`;
    const nostrSecret = '02'.padStart(64, '0');
    const context = randomBytes(32).toString('base64url');
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { format: 'pem', type: 'spki' }, privateKeyEncoding: { format: 'pem', type: 'pkcs8' } });
    const address = privateKeyToAccount(ethereumSecret).address;
    await setup.query('INSERT INTO ethereum_keys (id,"userId","keyType","sealedBlob",address,"archivedAt") VALUES ($1,$2,$3,$4,$5,now())', ['eth-old', 'user-eth', 'MANAGED', await seal(ethereumSecret, old('openkey/user/user-eth/keys')), address]);
    await setup.query('INSERT INTO ethereum_keys (id,"userId","sealingContext","keyType","sealedBlob",address) VALUES ($1,NULL,$2,$3,$4,$5)', ['eth-orphan', context, 'MANAGED', await seal(ethereumSecret, old('openkey/key/' + context)), address]);
    await setup.query('INSERT INTO ethereum_keys (id,"userId","keyType","sealedBlob",address) VALUES ($1,NULL,$2,NULL,$3)', ['external', 'EXTERNAL', address]);
    await setup.query('INSERT INTO nostr_keys (id,"userId","sealingContext","sealedSecret","pubkeyHex") VALUES ($1,$2,$3,$4,$5)', ['nostr', 'user-nostr', context, await seal(nostrSecret, old('openkey/key/' + context)), deriveNostrPubkey(nostrSecret)]);
    await setup.query('INSERT INTO user_encryption_key (id,"userId","sealedPrivateKey","publicKey") VALUES ($1,$2,$3,$4)', ['legacy', 'user-rsa', await seal(rsa.privateKey, old('openkey/user/user-rsa/encryption')), rsa.publicKey]);
    const holders = await Promise.all([0, 1, 2].map(() => webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])));
    const publicHolders = await Promise.all(holders.map(async (key, i) => ({ id: 'holder-' + i, publicKey: Buffer.from(await webcrypto.subtle.exportKey('raw', key.publicKey)).toString('base64url') })));
    const bundle = await withFencedOpenKeySnapshot(database, async snapshot => {
      const paths = snapshot.inventory.paths.map(path => ({ ...path, derivedPublicKey: vector.header.paths[0]!.derivedPublicKey, sourcePublicKey: vector.header.paths[0]!.sourcePublicKey, signatureChain: [...vector.header.paths[0]!.signatureChain] }));
      const manifest = encodeRecordManifest(snapshot.inventory.records.map(row => ({ table: row.table, rowId: row.id, owner: row.owner, path: row.path, purpose: row.purpose, version: row.version, transform: row.transform, expectedIdentity: row.expectedIdentity, ciphertextChecksum: row.ciphertextChecksum })), paths);
      const policy: ExportPolicy = { ...vector.header as ExportPolicy, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600000).toISOString(), snapshotId: snapshot.snapshotId, dbSnapshotHash: snapshot.ciphertextSnapshotHash, recordManifestHash: createHash('sha256').update(manifest).digest('hex'), paths, holders: publicHolders };
      const exportOptions = { enabled: true, policy, authorize: async () => true as const, isInTee: () => true, getExportQuote: async (hash: string) => ({ quote: 'synthetic', eventLog: '[]', reportDataSha256: hash }), snapshot: async <T>(operation: (keys: { path: string; purpose: string; version: number; key: Uint8Array }[]) => Promise<T>) => operation(paths.map(path => ({ ...path, key: old(path.path) }))), validateSnapshot: async (_: ExportPolicy, keys: readonly { path: string; purpose: string; version: number; key: Uint8Array }[]) => validateOpenKeySnapshot(snapshot.inventory.records, snapshot.inventory.paths, keys) };
      const dry = await prepareEscrowExport(exportOptions);
      expect(dry.dryRun).toBe(true); expect(dry.expectedRecords).toBe(4);
      return prepareEscrowExport({ ...exportOptions, dryRun: false });
    });
    if (bundle.dryRun) throw new Error('Expected real synthetic export');
    const shares = await Promise.all(bundle.wrappers.slice(0, 2).map(wrapper => unwrapEscrowShare(wrapper, holders[Number(wrapper.holderId.slice(-1))]!, { escrowId: bundle.header.escrowId, holderId: wrapper.holderId, x: wrapper.x, headerHash: bundle.headerHash })));
    const targetFields = { targetAppId: measurement.appId, targetComposeHash: measurement.composeHash, targetImageDigest: measurement.imageDigest, targetCodeHash: measurement.codeHash, bootReference: measurement.bootReference };
    const targetPolicy = await deriveRecoveryTargetPolicy(runtime, targetFields);
    const sessions = new EscrowRecoverySessions({ enabled: true, isInTee: runtime.isInTee, quote: async hash => ({ quote: 'synthetic', eventLog: '[]', reportDataSha256: hash }) });
    const session = await sessions.create(bundle.headerHash, { ...targetFields, newPolicyId: targetPolicy.newPolicyId });
    const options = { enabled: true, database, runtime, descriptor: session.descriptor, header: bundle.header, items: bundle.items, shares };
    for (const place of [{ database: 'production', address: null }, { database: name, address: '192.0.2.1' }]) {
      const statements: string[] = [];
      const guarded = { $transaction: async <T>(operation: (tx: import('../services/escrow-snapshot').EscrowSqlTransaction) => Promise<T>) => operation({
        $executeRawUnsafe: async (query: string) => { statements.push(query); return 0; },
        $queryRawUnsafe: async <T>(query: string) => { statements.push(query); return [place] as T; },
      }) };
      await expect(restoreOpenKeyDrill({ ...options, database: guarded })).rejects.toThrow('local drill');
      expect(statements).toEqual(['LOCK TABLE "ethereum_keys", "nostr_keys", "user_encryption_key" IN EXCLUSIVE MODE', 'SELECT current_database() AS database, inet_server_addr()::text AS address']);
    }
    const before = await withFencedOpenKeySnapshot(database, async snapshot => snapshot.ciphertextSnapshotHash);
    await expect(restoreOpenKeyDrill({ ...options, enabled: false })).rejects.toThrow('disabled');
    await setup.query('UPDATE ethereum_keys SET label = $1 WHERE id = $2', ['changed', 'eth-old']);
    await expect(restoreOpenKeyDrill(options)).rejects.toThrow('snapshot');
    await setup.query('UPDATE ethereum_keys SET label = NULL WHERE id = $1', ['eth-old']);
    const sameKeyRuntime = { ...runtime, derivePath: async (path: string) => { const evidence = await runtime.derivePath(path); if (path === 'openkey/escrow/recovery-provenance/v1') return evidence; evidence.key.fill(0); return { ...evidence, key: old(path) }; } };
    await expect(restoreOpenKeyDrill({ ...options, runtime: sameKeyRuntime })).rejects.toThrow('new sealing policy');
    await setup.query(`CREATE FUNCTION sabotage() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW."sealedSecret" := 'corrupted'; RETURN NEW; END $$`);
    await setup.query('CREATE TRIGGER sabotage BEFORE UPDATE ON nostr_keys FOR EACH ROW EXECUTE FUNCTION sabotage()');
    await expect(restoreOpenKeyDrill(options)).rejects.toThrow('write verification');
    expect(await withFencedOpenKeySnapshot(database, async snapshot => snapshot.ciphertextSnapshotHash)).toBe(before);
    expect((await setup.query('SELECT * FROM escrow_restore_receipt')).rows).toHaveLength(0);
    await setup.query('DROP TRIGGER sabotage ON nostr_keys');
    const packets = await Promise.all(shares.map((share, i) => wrapRecoveryShare(share, session.descriptor, bundle.wrappers[i]!.holderId, share[32]!)));
    const result = await sessions.consume(session.descriptor.sessionId, session.descriptorHash, bundle.header, packets, async opened => {
      const attempts = await Promise.all([restoreOpenKeyDrill({ ...options, shares: opened }), restoreOpenKeyDrill({ ...options, shares: opened })]);
      expect(attempts.every(receipt => receipt.completed === 4)).toBe(true);
      return attempts[0]!;
    });
    expect(result.completed).toBe(4);
    expect(buffers.every(key => key.every(byte => byte === 0))).toBe(true);
    const after = await withFencedOpenKeySnapshot(database, async snapshot => {
      expect(snapshot.ciphertextSnapshotHash).not.toBe(before);
      const material = snapshot.inventory.paths.filter(path => path.expectedCount > 0).map(path => ({ ...path, key: fresh(path.path) }));
      expect(validateOpenKeySnapshot(snapshot.inventory.records, snapshot.inventory.paths, material).reduce((count, path) => count + path.validatedCount, 0)).toBe(4);
      for (const key of material) key.key.fill(0);
      const ethereum = snapshot.inventory.records.find(row => row.id === 'eth-old')!;
      expect(await unseal(ethereum.blob, fresh(ethereum.path))).toBe(ethereumSecret);
      await expect(unseal(ethereum.blob, old(ethereum.path))).rejects.toThrow();
      return snapshot.ciphertextSnapshotHash;
    });
    expect((await restoreOpenKeyDrill(options)).completed).toBe(4);
    expect(await withFencedOpenKeySnapshot(database, async snapshot => snapshot.ciphertextSnapshotHash)).toBe(after);
    const changed = { ...options.descriptor, nonce: randomBytes(32).toString('base64url') };
    await expect(restoreOpenKeyDrill({ ...options, descriptor: changed })).rejects.toThrow('receipt');
    expect((await setup.query('SELECT * FROM escrow_restore_receipt')).rows).toHaveLength(1);
    const firstLock = queries.findIndex(query => query.includes('IN EXCLUSIVE MODE'));
    expect(firstLock).toBeGreaterThan(0);
    expect(queries[firstLock]).toBe('LOCK TABLE \"ethereum_keys\", \"nostr_keys\", \"user_encryption_key\" IN EXCLUSIVE MODE');
    for (const share of shares) share.fill(0);
  } finally {
    await prisma.$disconnect(); await setup.end();
    await control.query(`DROP DATABASE "${name}"`); await control.end();
  }
}, 30000);


test('shipped recovery drill is disabled before runtime or database access', async () => {
  const script = `import { createOpenKeyRecoveryDrillService } from ${JSON.stringify(new URL('../services/escrow-recovery-drill.ts', import.meta.url).pathname)};
const service = createOpenKeyRecoveryDrillService({ $transaction: async () => { throw new Error('DB accessed'); } }, async () => { throw new Error('Runtime accessed'); });
for (const operation of [() => service.create('a'.repeat(64)), () => service.complete({})]) {
  try { await operation(); process.exit(2); } catch(e) { if(e.message !== 'Recovery drill disabled') process.exit(3); }
}`;
  const child = Bun.spawn([process.execPath, '-e', script], { env: {}, stdout: 'pipe', stderr: 'pipe' });
  expect(await child.exited, await new Response(child.stderr).text()).toBe(0);
});
