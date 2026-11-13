import type { PrismaClient } from '@openkey/db';
import { EscrowRecoverySessions, deriveRecoveryTargetPolicy, type RecoveryDescriptor, type RecoveryShareEnvelope, type EscrowHeader, type EscrowCiphertextItem } from '@openkey/tee';
import configured from './escrow-recovery-config.json';
import { createProductionOpenKeyEscrowRuntime } from './escrow-service';
import { createPrismaEscrowDatabase } from './escrow-prisma';
import { restoreOpenKeyDrill } from './escrow-restore-drill';

/** Internal measured drill entry, deliberately not mounted on an HTTP route. */
export function createOpenKeyRecoveryDrillService(database: Pick<PrismaClient, '$transaction'>, getRuntime = createProductionOpenKeyEscrowRuntime) {
  const descriptors = new Map<string, RecoveryDescriptor>();
  const runtime = () => getRuntime();
  const sessions = new EscrowRecoverySessions({ enabled: configured.enabled === true,
    isInTee: async () => (await runtime()).isInTee(),
    // Explicit recovery domain; the export quote callback is never used here.
    quote: async hash => (await runtime()).getRecoveryQuote(hash),
  });
  const requireEnabled = () => { if (configured.enabled !== true) throw new Error('Recovery drill disabled'); };
  return {
    async create(exportHeaderHash: string) {
      requireEnabled();
      for (const [id, d] of descriptors) if (Date.parse(d.expiresAt) <= Date.now()) descriptors.delete(id);
      const client = await runtime(), measurement = await client.measurement();
      const target = { targetAppId: measurement.appId, targetComposeHash: measurement.composeHash, targetImageDigest: measurement.imageDigest, targetCodeHash: measurement.codeHash, bootReference: measurement.bootReference };
      const policy = await deriveRecoveryTargetPolicy(client, target);
      const session = await sessions.create(exportHeaderHash, { ...target, newPolicyId: policy.newPolicyId });
      descriptors.set(session.descriptor.sessionId, session.descriptor);
      return { ...session, targetPolicyEvidence: policy.targetPolicyEvidence };
    },
    async complete(input: { sessionId: string; descriptorHash: string; header: EscrowHeader; items: readonly EscrowCiphertextItem[]; envelopes: readonly RecoveryShareEnvelope[] }) {
      requireEnabled();
      const request = structuredClone(input), descriptor = descriptors.get(request.sessionId);
      if (!descriptor) throw new Error('Recovery session unavailable');
      return sessions.consume(request.sessionId, request.descriptorHash, request.header, request.envelopes, async shares => {
        descriptors.delete(request.sessionId);
        return restoreOpenKeyDrill({ enabled: true, database: createPrismaEscrowDatabase(database), runtime: await runtime(),
          descriptor, header: request.header, items: request.items, shares });
      });
    },
  };
}
