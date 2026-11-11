import { isDeepStrictEqual } from 'node:util';
import { randomBytes } from 'node:crypto';
import { decodeBase58, encodeBase58, getBytes, toBeHex } from 'ethers';
import { activateSessionWithHost } from '@tinycloud/sdk-core';
import { ensureEip55, completeSessionSetup } from '@tinycloud/node-sdk-wasm';
import type { PortableDelegation } from '@tinycloud/node-sdk';
import type { PrismaClient } from '@openkey/db';
import { prepareDelegationSession, parsePreparedRecap } from '../routes/delegate-session';
import { signManagedKey } from './managed-key-signing';
import { lockReviewer } from './reviewer-accounts';
import { recordReviewerWriter } from './reviewer-cleanup';
import { appleReviewEnabled, reviewerSeedPermissions } from './reviewer-apple-policy';

export function reviewerJwkFromDid(did: unknown) {
  if (typeof did !== 'string' || !/^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$/.test(did)) throw new Error('Reviewer audience refused');
  const bytes = getBytes(toBeHex(decodeBase58(did.slice(9)), 34));
  if (bytes[0] !== 0xed || bytes[1] !== 0x01 || 'did:key:z' + encodeBase58(bytes) !== did) throw new Error('Reviewer audience refused');
  return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(bytes.slice(2)).toString('base64url') };
}

// All bytes and resources are built here. Callers supply a public recipient,
// never owner material or a message for the owner to sign.
export async function buildSeedGrant(
  key: { address: string; userId: string | null; sealedBlob: string; sealingContext: string | null },
  spaceId: string, nodeHost: string, sessionDid: string,
  dryRun: boolean, expiresAt: Date,
): Promise<{ delegation: PortableDelegation; siwe: string; signature: `0x${string}` }> {
  const permissions = reviewerSeedPermissions(dryRun);
  const now = new Date();
  if (expiresAt <= now || expiresAt.getTime() - now.getTime() > 3600_000) throw new Error('Reviewer grant lifetime refused');
  const prepared = prepareDelegationSession({ address: ensureEip55(key.address), chainId: 1, prefix: 'applications',
    jwk: reviewerJwkFromDid(sessionDid), permissions, issuedAt: now, expiryMs: expiresAt.getTime() - now.getTime(),
    domain: 'openkey.so', nonce: randomBytes(16).toString('hex'),
  });
  if (prepared.spaceId !== spaceId) throw new Error('Reviewer grant target refused');
  const signature = await signManagedKey(key, key.sealedBlob, prepared.prepared.siwe);
  const complete = completeSessionSetup({ ...prepared.prepared, signature });
  const resources = parsePreparedRecap(prepared.prepared.siwe);
  const first = resources[0]!;
  const delegation: PortableDelegation = { cid: complete.delegationCid, delegationHeader: complete.delegationHeader, spaceId,
    path: first.path, actions: first.actions, resources, delegateDID: sessionDid,
    ownerAddress: key.address, chainId: 1, host: nodeHost, expiry: expiresAt,
    disableSubDelegation: false,
  };
  return { delegation, siwe: prepared.prepared.siwe, signature };
}

type SeedRequest = { kind: string; version: number; requestId: string; createdAt: string; sessionDid: string; requested: unknown; requestedExpiry: string };
type SeedRun = { requestId: string; createdAt: string; sessionDid: string; dryRun: boolean; installEpoch: number; expiresAt: string };
export async function reviewerSeedGrant(database: PrismaClient, request: SeedRequest, dryRun: boolean) {
  if (!appleReviewEnabled() || !request || Object.keys(request).sort().join(',') !== 'createdAt,kind,requestId,requested,requestedExpiry,sessionDid,version'
    || request.kind !== 'tinycloud.auth.request' || request.version !== 1
    || typeof request.requestId !== 'string' || !/^reviewer-seed-[a-zA-Z0-9-]{1,100}$/.test(request.requestId)
    || typeof request.createdAt !== 'string' || !Number.isFinite(Date.parse(request.createdAt))
    || Date.parse(request.createdAt) > Date.now() + 30_000 || Date.parse(request.createdAt) < Date.now() - 3600_000
    || request.requestedExpiry !== '1h' || !isDeepStrictEqual(request.requested, reviewerSeedPermissions(dryRun))) {
    throw new Error('Reviewer seed request refused');
  }
  reviewerJwkFromDid(request.sessionDid);
  const issued = await database.$transaction(async tx => {
    const binding = await lockReviewer(tx, 'apple');
    if (!binding.userId || !binding.user?.reviewerHoldAt || binding.seededAt || !binding.keyId || !binding.spaceId || !binding.nodeHost) {
      throw new Error('Reviewer seed is not available');
    }
    if (dryRun && binding.seedStartedAt) throw new Error('Reviewer write run already started');
    const prior = dryRun ? null : binding.seedRun as SeedRun | null;
    const run: SeedRun = prior ?? { requestId: request.requestId, createdAt: request.createdAt,
      sessionDid: request.sessionDid, dryRun, installEpoch: binding.installEpoch, expiresAt: new Date(Date.now() + 3600_000).toISOString() };
    if ((!dryRun && binding.seedStartedAt && !prior) || run.installEpoch !== binding.installEpoch || run.requestId !== request.requestId
      || run.createdAt !== request.createdAt || run.sessionDid !== request.sessionDid || run.dryRun !== dryRun
      || Date.parse(run.expiresAt) <= Date.now()) throw new Error('Reviewer seed run ended; reset required');
    const key = await tx.ethereumKey.findFirst({ where: { id: binding.keyId, userId: binding.userId, archivedAt: null } });
    if (!key?.sealedBlob) throw new Error('Reviewer seed key unavailable');
    if (!dryRun) await tx.reviewerAccount.update({ where: { store: 'apple' }, data: { seedRun: run, seedStartedAt: binding.seedStartedAt ?? new Date() } });
    const expiresAt = new Date(run.expiresAt);
    const { delegation } = await buildSeedGrant({ ...key, sealedBlob: key.sealedBlob }, binding.spaceId, binding.nodeHost, request.sessionDid, dryRun, expiresAt);
    if (!dryRun) await recordReviewerWriter(tx, binding, expiresAt);
    return { userId: binding.userId, epoch: binding.installEpoch, nodeHost: binding.nodeHost, spaceId: binding.spaceId,
      artifact: { kind: 'tinycloud.auth.delegation', version: 1, requestId: request.requestId,
        delegationCid: delegation.cid, delegation, permissions: reviewerSeedPermissions(dryRun), expiry: expiresAt.toISOString(), prompted: false } };
  }, { timeout: 15_000 });
  // Session-only receivers consume an already registered owner delegation.
  // Record the actual expiry before this RPC, including unknown outcomes.
  const activation = await activateSessionWithHost(issued.nodeHost, issued.artifact.delegation.delegationHeader);
  if (!activation.success || !(activation.activated?.includes(issued.spaceId)
    || (activation.activated?.length === 0 && activation.skipped?.length === 0))) throw new Error('Reviewer seed activation refused');
  await database.$transaction(async tx => {
    const current = await lockReviewer(tx, 'apple');
    if (current.userId !== issued.userId || current.installEpoch !== issued.epoch || !current.user?.reviewerHoldAt
      || (dryRun ? Boolean(current.seedStartedAt) : (current.seedRun as SeedRun | null)?.requestId !== request.requestId)) throw new Error('Reviewer seed run superseded');
  });
  return issued.artifact;
}

// The report is an operator attestation from the pinned Home readers; it is
// not a substitute for the marker read through owner-authorized node access.
export async function verifyReviewerSeed(database: PrismaClient, report: any) {
  if (!appleReviewEnabled()) throw new Error('Reviewer seed verification refused');
  const binding = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'apple' }, include: { user: true } });
  const run = binding.seedRun as SeedRun | null;
  const key = binding.keyId ? await database.ethereumKey.findFirst({ where: { id: binding.keyId, userId: binding.userId } }) : null;
  if (!key?.sealedBlob || !binding.user?.reviewerHoldAt || !binding.spaceId || !binding.nodeHost || binding.seededAt
    || !run || run.dryRun || run.installEpoch !== binding.installEpoch || Date.parse(run.expiresAt) <= Date.now()
    || !report || report.seed !== 'tinychat-reviewer-seed' || report.revision !== 1
    || !['seeded', 'resumed', 'already-seeded'].includes(report.status) || report.spaceId !== binding.spaceId
    || report.ownerDid !== `did:pkh:eip155:1:${key.address}`
    || report.readBack?.chats?.length !== 1 || report.readBack.chats[0]?.messages !== 4
    || !Array.isArray(report.readBack?.feedCards) || new Set(report.readBack.feedCards).size !== 4
    || report.readBack.feedCards.some((value: unknown) => typeof value !== 'string')
    || report.readBack?.voiceNotes?.length !== 1 || !(report.readBack.voiceNotes[0]?.transcriptSegments > 0)) {
    throw new Error('Reviewer seed verification refused');
  }
  const { TinyCloudNode } = await import('@tinycloud/node-sdk');
  const { unsealManagedKey } = await import('./managed-key-signing');
  const node = new TinyCloudNode({ host: binding.nodeHost, privateKey: await unsealManagedKey(key, key.sealedBlob),
    prefix: 'applications', sessionExpirationMs: 60_000, autoCreateSpace: false,
    autoBootstrapAccount: false, enablePublicSpace: false, includeAccountRegistryPermissions: false, autoDiscoverLocalNode: false });
  await node.signIn();
  const result = await node.sqlForSpace(binding.spaceId).db('xyz.tinycloud.tinychat/threads')
    .query<string>('SELECT value FROM settings WHERE key = ?', ['xyz.tinycloud.tinychat:reviewer-seed']);
  let marker: any;
  try { marker = result.ok && result.data.rows.length === 1 ? JSON.parse(result.data.rows[0]?.[0] ?? '') : null; }
  catch { throw new Error('Reviewer seed verification refused'); }
  if (marker?.seed !== 'tinychat-reviewer-seed' || marker.revision !== 1 || marker.state !== 'complete' || marker.seededAt !== report.seededAt) {
    throw new Error('Reviewer seed verification refused');
  }
  await database.$transaction(async tx => {
    const current = await lockReviewer(tx, 'apple');
    if (current.userId !== binding.userId || current.installEpoch !== binding.installEpoch
      || !current.user?.reviewerHoldAt || !isDeepStrictEqual(current.seedRun, binding.seedRun)) throw new Error('Reviewer seed verification superseded');
    await tx.reviewerAccount.update({ where: { store: 'apple' }, data: { seededAt: new Date() } });
  });
}
