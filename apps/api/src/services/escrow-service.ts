import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { PrismaClient } from '@openkey/db';
import { createProductionEscrowProvenanceClient, encodeRecordManifest, freezeEscrowPreflightPolicy, prepareEscrowExport, type EscrowPathKey, type ExportPolicy } from '@openkey/tee';
import configured from './escrow-config.json';
import build from './escrow-build.json';
import admins from './escrow-admins.json';
import { verifyEscrowApprovalSignatures, verifyEscrowPreflightSignature, assertEscrowApprovalMatches, type EscrowApprovalRequest, type EscrowPreflightRequest } from './escrow-approval';
import { lockEscrowAuthorization, consumeEscrowAuthorization } from './escrow-approval-store';
import { createPrismaEscrowDatabase } from './escrow-prisma';
import { withFencedOpenKeySnapshot } from './escrow-snapshot';
import { storeEscrowPreflight, loadEscrowPreflight, type StoredEscrowPreflight } from './escrow-preflight-store';
import { encodeOpenKeyDbSnapshot } from './escrow-db-encoding';
import { validateOpenKeySnapshot } from './escrow-validate';
import { escrowMeasurementFromInfo, type EscrowMeasurement } from './escrow-measurement';

type Runtime = Awaited<ReturnType<typeof createProductionEscrowProvenanceClient>> & { measurement(): Promise<EscrowMeasurement> };
type Snapshot = Parameters<Parameters<typeof withFencedOpenKeySnapshot>[1]>[0];
type Database = Pick<PrismaClient, '$transaction' | '$queryRawUnsafe' | '$executeRawUnsafe'>;
const settings = structuredClone(configured) as { enabled: boolean; serviceName: string; agentVersion: string; holders: { id: string; publicKey: string }[] };
const adminIds = (admins as { id: string; publicKey: string }[]).map(admin => admin.id);
const hash = (bytes: string | Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const pathIdentity = (path: { path: string; purpose: string; version: number; transform: string }) => JSON.stringify([path.path, path.purpose, path.version, path.transform]);

async function productionRuntime(): Promise<Runtime> {
  const client = await createProductionEscrowProvenanceClient();
  return { ...client, measurement: async () => escrowMeasurementFromInfo(await client.getRuntimeInfo(), build.codeHash,
    readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(), settings.agentVersion) };
}

async function withPreparedInventory<T>(snapshot: Snapshot, runtime: Runtime, operation: (prepared: {
  material: EscrowPathKey[]; paths: ExportPolicy['paths']; recordManifestUtf8: string; dbSnapshotUtf8: string;
}) => Promise<T>): Promise<T> {
  const derived = new Map<string, Awaited<ReturnType<Runtime['derivePath']>>>();
  const material: EscrowPathKey[] = [];
  try {
    for (const path of snapshot.inventory.paths.filter(path => path.expectedCount > 0)) {
      if (!derived.has(path.path)) derived.set(path.path, await runtime.derivePath(path.path));
      material.push({ path: path.path, purpose: path.purpose, version: path.version, key: derived.get(path.path)!.key.slice() });
    }
    if (derived.size === 0) derived.set('openkey/escrow/provenance/v1', await runtime.derivePath('openkey/escrow/provenance/v1'));
    const fallback = derived.values().next().value!;
    const paths = snapshot.inventory.paths.map(path => {
      const evidence = derived.get(path.path) ?? fallback;
      return { ...path, derivedPublicKey: evidence.derivedPublicKey, sourcePublicKey: evidence.sourcePublicKey, signatureChain: [...evidence.signatureChain] };
    });
    const entries = snapshot.inventory.records.map(record => ({ table: record.table, rowId: record.id, owner: record.owner, path: record.path, purpose: record.purpose,
      version: record.version, transform: record.transform, expectedIdentity: record.expectedIdentity, ciphertextChecksum: record.ciphertextChecksum }));
    const recordManifestUtf8 = new TextDecoder().decode(encodeRecordManifest(entries, paths));
    const dbSnapshotUtf8 = new TextDecoder().decode(encodeOpenKeyDbSnapshot(snapshot.rows));
    return await operation({ material, paths, recordManifestUtf8, dbSnapshotUtf8 });
  } finally {
    for (const result of derived.values()) result.key.fill(0);
    for (const item of material) item.key.fill(0);
  }
}

/** Service-only dependencies; HTTP input supplies no policy or measurement fields. */
export function createOpenKeyEscrowService(database: Database, getRuntime: () => Promise<Runtime> = productionRuntime) {
  const fenced = createPrismaEscrowDatabase(database);
  const measuredConfigHash = hash(JSON.stringify(['tinycloud/escrow/measured-config', 1, settings, admins, build.codeHash]));
  const enabled = () => settings.enabled === true && settings.serviceName === 'api' && typeof build.codeHash === 'string' && /^[a-f0-9]{64}$/.test(build.codeHash);
  const requireEnabled = () => { if (!enabled()) throw new Error('Escrow disabled'); };
  return {
    enabled, measuredConfigHash,
    async preflight(request: { approval: EscrowPreflightRequest; approverId: string }) {
      requireEnabled();
      if (!adminIds.includes(request.approverId) || request.approverId === request.approval.adminId) throw new Error('Invalid approver');
      const verified = await verifyEscrowPreflightSignature(request.approval, measuredConfigHash);
      return withFencedOpenKeySnapshot(fenced, async snapshot => {
        const runtime = await getRuntime();
        if (await runtime.isInTee() !== true) throw new Error('Guest unavailable');
        const measurement = await runtime.measurement();
        return withPreparedInventory(snapshot, runtime, async prepared => {
          const counts = validateOpenKeySnapshot(snapshot.inventory.records, snapshot.inventory.paths, prepared.material);
          if (Date.parse(request.approval.expiresAt) <= Date.now()) throw new Error('Preflight expired');
          const nonce = randomBytes(32).toString('base64url');
          const policy: ExportPolicy = { version: 1, ...measurement, escrowId: randomUUID(), createdAt: new Date().toISOString(), expiresAt: request.approval.expiresAt,
            snapshotId: snapshot.snapshotId, recordManifestHash: hash(prepared.recordManifestUtf8), dbSnapshotHash: hash(prepared.dbSnapshotUtf8), nonce,
            approvalReference: `escrow:${nonce}`, operatorId: request.approval.adminId, approverId: request.approverId, holders: structuredClone(settings.holders), paths: prepared.paths };
          const policyHash = await storeEscrowPreflight(snapshot.tx, { policy, recordManifestUtf8: prepared.recordManifestUtf8, dbSnapshotUtf8: prepared.dbSnapshotUtf8 });
          const byPurpose = { ethereum: 0, nostr: 0, legacy: 0, sentinel: 0 };
          for (const path of prepared.paths) {
            if (path.purpose === 'ethereum') byPurpose.ethereum += path.expectedCount;
            else if (path.purpose === 'nostr') byPurpose.nostr += path.expectedCount;
            else if (path.purpose === 'legacy-user-encryption') byPurpose.legacy += path.expectedCount;
            else if (path.purpose === 'legacy-user-encryption-empty') byPurpose.sentinel++;
          }
          return { policyHash, recordManifestHash: policy.recordManifestHash, dbSnapshotHash: policy.dbSnapshotHash,
            approvalDescriptor: { policyHash, nonce, expiresAt: policy.expiresAt, dryRun: false as const, operatorId: policy.operatorId, approverId: policy.approverId },
            counts: counts.map((count, index) => ({ pathHash: hash(pathIdentity(prepared.paths[index]!)), validatedCount: count.validatedCount })),
            summary: { appId: policy.appId, composeHash: policy.composeHash, imageDigest: policy.imageDigest,
              holders: policy.holders.map(holder => ({ id: holder.id, publicKeyFingerprint: hash(Buffer.from(holder.publicKey, 'base64url')) })),
              byPurpose, totalRows: snapshot.inventory.records.length, createdAt: policy.createdAt, expiresAt: policy.expiresAt } };
        });
      }, async tx => {
        await lockEscrowAuthorization(tx);
        await consumeEscrowAuthorization(tx, { kind: 'preflight', policyHash: measuredConfigHash, nonce: verified.nonce, expiresAt: verified.expiresAt, operatorId: verified.adminId, approverId: null, dryRun: true });
      });
    },
    async export(request: { approval: EscrowApprovalRequest }) {
      requireEnabled();
      const verified = await verifyEscrowApprovalSignatures(request.approval);
      let stored: StoredEscrowPreflight;
      let expected: Omit<EscrowApprovalRequest, 'signatures'>;
      return withFencedOpenKeySnapshot(fenced, async snapshot => {
        const runtime = await getRuntime();
        if (await runtime.isInTee() !== true) throw new Error('Guest unavailable');
        const measurement = await runtime.measurement();
        return withPreparedInventory(snapshot, runtime, async prepared => {
          if (hash(prepared.recordManifestUtf8) !== stored.policy.recordManifestHash || hash(prepared.dbSnapshotUtf8) !== stored.policy.dbSnapshotHash) throw new Error('Snapshot changed');
          const previous = new Map(stored.policy.paths.map(path => [pathIdentity(path), path]));
          const paths = prepared.paths.map(path => {
            const old = previous.get(pathIdentity(path));
            if (!old || old.sourcePublicKey !== path.sourcePublicKey || old.derivedPublicKey !== path.derivedPublicKey) throw new Error('Source provenance changed');
            return { ...path, signatureChain: [...old.signatureChain] };
        });
        const policy: ExportPolicy = { ...stored.policy, ...measurement, paths, holders: structuredClone(settings.holders) };
        if ((await freezeEscrowPreflightPolicy(policy)).hash !== expected.policyHash) throw new Error('Policy changed');
        const bundle = await prepareEscrowExport({ enabled: true, dryRun: false, policy, isInTee: () => runtime.isInTee(),
          authorize: async candidate => { if ((await freezeEscrowPreflightPolicy(candidate)).hash !== expected.policyHash) throw new Error('Policy changed'); return true; },
          snapshot: async operation => operation(prepared.material),
          validateSnapshot: async (_policy, keys) => validateOpenKeySnapshot(snapshot.inventory.records, snapshot.inventory.paths, keys),
          getExportQuote: headerHash => runtime.getExportQuote(headerHash) });
        if (bundle.dryRun) throw new Error('Incomplete export');
        const total = snapshot.inventory.records.length;
        const inserted = await snapshot.tx.$executeRawUnsafe(
          'INSERT INTO "escrow_archive" ("escrowId", "headerHash", "bundle", "recordManifestUtf8", "dbSnapshotUtf8", "sourceSnapshotId", "exportSnapshotId", "expectedRecords", "completedRecords", "createdAt") VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7,$8,$8,clock_timestamp())',
          policy.escrowId, bundle.headerHash, JSON.stringify(bundle), prepared.recordManifestUtf8, prepared.dbSnapshotUtf8, policy.snapshotId, snapshot.snapshotId, total);
        if (inserted !== 1) throw new Error('Archive incomplete');
        await snapshot.tx.$executeRawUnsafe('DELETE FROM "escrow_archive" WHERE "escrowId" IN (SELECT "escrowId" FROM "escrow_archive" ORDER BY "createdAt" DESC, "escrowId" DESC OFFSET 2)');
        return { archiveId: policy.escrowId, bundle };
        });
      }, async tx => {
        await lockEscrowAuthorization(tx);
        stored = await loadEscrowPreflight(tx, verified.policyHash);
        expected = { policyHash: (await freezeEscrowPreflightPolicy(stored.policy)).hash, nonce: stored.policy.nonce,
          expiresAt: stored.policy.expiresAt, dryRun: false, operatorId: stored.policy.operatorId, approverId: stored.policy.approverId };
        assertEscrowApprovalMatches(verified, expected);
        const { signatures: _signatures, ...audit } = verified;
        await consumeEscrowAuthorization(tx, { ...audit, kind: 'export' });
      });
    },
  };
}
