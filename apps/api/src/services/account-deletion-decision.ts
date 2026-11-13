import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';
import type { DeletionHostSnapshot } from './account-deletion-request';

export type DependencyTarget = { resourceId: string; targetResourceHmac: string; dependentCount: number; dependencyFingerprint: string; fingerprintKeyId: string };
export type ResourceDependencyObservation = { hostId: string; ownerHmac: string; dependentResourceCount: number; resourceHmacs: string[]; targets: DependencyTarget[] };
export type TargetRow = [string, number, string, string];
export type HostRow = [string, string, number, string[], TargetRow[]];
export type ReviewDecisionProof = { payload: unknown[]; signature: string };
export interface ReviewDecisionSigner {
  writerId: string;
  keyId: string;
  // Production implementation must use the dedicated sealed-TEE key.
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}
const hashPattern = /^[0-9a-f]{64}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const keyPattern = /^[a-z0-9-]{1,64}$/;
export const reviewDecisionDomain = 'tinycloud-resource-review-decision-v1\0';

export function reviewJcs(value: unknown): string {
  const result = canonicalize(value);
  if (typeof result !== 'string') throw new Error('Invalid review JSON');
  return result;
}
export function validateDependencyObservation(value: ResourceDependencyObservation, inventory: readonly string[]): void {
  const safeCount = (count: number) => Number.isSafeInteger(count) && count >= 0;
  const ordered = (values: string[]) => values.every((item, index) => hashPattern.test(item) && (index === 0 || item > values[index - 1]!));
  if (!/^[a-z0-9-]{1,63}$/.test(value.hostId) || !hashPattern.test(value.ownerHmac) || !safeCount(value.dependentResourceCount) || !Array.isArray(value.resourceHmacs) || !ordered(value.resourceHmacs) || value.dependentResourceCount !== value.resourceHmacs.length || !Array.isArray(value.targets) || value.targets.length !== new Set(inventory).size) throw new Error('Incomplete dependency observation');
  const seen = new Set<string>();
  let previous = '';
  for (const target of value.targets) {
    if (!target || typeof target.resourceId !== 'string' || !inventory.includes(target.resourceId) || seen.has(target.resourceId) || !hashPattern.test(target.targetResourceHmac) || target.targetResourceHmac <= previous || !safeCount(target.dependentCount) || !hashPattern.test(target.dependencyFingerprint) || !keyPattern.test(target.fingerprintKeyId)) throw new Error('Invalid dependency target mapping');
    seen.add(target.resourceId);
    previous = target.targetResourceHmac;
  }
}

export function buildReviewSnapshot(snapshot: DeletionHostSnapshot, observations: ResourceDependencyObservation[]): HostRow[] {
  const hosts = snapshot.configured;
  if (snapshot.uncertain || !hosts.length || new Set(hosts.map(host => host.hostId)).size !== hosts.length || new Set(hosts.map(host => host.url)).size !== hosts.length || snapshot.recorded.some(host => !hosts.some(configured => configured.url === host)) || observations.length !== hosts.length || new Set(observations.map(row => row.hostId)).size !== hosts.length) throw new Error('Incomplete review host snapshot');
  return [...hosts].sort((a, b) => a.hostId < b.hostId ? -1 : a.hostId > b.hostId ? 1 : 0).map(host => {
    const row = observations.find(observation => observation.hostId === host.hostId);
    if (!row) throw new Error('Missing review host');
    validateDependencyObservation(row, row.targets.map(target => target.resourceId));
    return [row.hostId, row.ownerHmac, row.dependentResourceCount, [...row.resourceHmacs], row.targets.map(target => [target.targetResourceHmac, target.dependentCount, target.dependencyFingerprint, target.fingerprintKeyId])];
  });
}

export function validateReviewSnapshot(snapshot: DeletionHostSnapshot, rows: HostRow[]): HostRow[] {
  const observations = rows.map(row => {
    if (!Array.isArray(row) || row.length !== 5 || !Array.isArray(row[4])) throw new Error('Invalid review snapshot');
    return { hostId: row[0], ownerHmac: row[1], dependentResourceCount: row[2], resourceHmacs: row[3], targets: row[4].map(target => {
      if (!Array.isArray(target) || target.length !== 4) throw new Error('Invalid review target row');
      return { resourceId: target[0], targetResourceHmac: target[0], dependentCount: target[1], dependencyFingerprint: target[2], fingerprintKeyId: target[3] };
    }) };
  });
  const checked = buildReviewSnapshot(snapshot, observations);
  if (reviewJcs(checked) !== reviewJcs(rows)) throw new Error('Noncanonical review snapshot');
  return checked;
}

async function signReviewDecision(
  decision: { decisionId: string; jobId: string; hostId: string; resourceId: string; disposition: 'proceed' | 'wait_for_re-encryption'; decisionMaker: string; decidedAt: number; reason: string; expiresAt: number; reviewedSnapshot?: HostRow[] },
  snapshot: DeletionHostSnapshot,
  observations: ResourceDependencyObservation[],
  signer?: ReviewDecisionSigner,
  trustedNow?: number,
): Promise<ReviewDecisionProof> {
  if (!signer || !keyPattern.test(signer.writerId) || !keyPattern.test(signer.keyId)) throw new Error('Review signing key unavailable');
  if (!uuidPattern.test(decision.decisionId) || !uuidPattern.test(decision.jobId) || !['proceed', 'wait_for_re-encryption'].includes(decision.disposition)) throw new Error('Invalid review decision identity');
  for (const value of [decision.decisionMaker, decision.reason]) {
    if (typeof value !== 'string' || !value || /[\x00-\x1f\x7f]/.test(value)) throw new Error('Invalid review decision text');
    reviewJcs(value);
  }
  const now = trustedNow ?? Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(decision.decidedAt) || !Number.isSafeInteger(decision.expiresAt) || decision.decidedAt < 0 || decision.decidedAt > now || decision.expiresAt <= now || decision.expiresAt <= decision.decidedAt || decision.expiresAt - decision.decidedAt > 172800) throw new Error('Invalid review decision lifetime');
  const currentRows = buildReviewSnapshot(snapshot, observations);
  const rows = decision.reviewedSnapshot ? validateReviewSnapshot(snapshot, decision.reviewedSnapshot) : currentRows;
  const host = observations.find(row => row.hostId === decision.hostId);
  const target = host?.targets.find(row => row.resourceId === decision.resourceId);
  if (!host || !target) throw new Error('Missing exact review target');
  const reviewedHost = rows.find(row => row[0] === decision.hostId);
  const reviewedTarget = reviewedHost?.[4].find(row => row[0] === target.targetResourceHmac);
  if (reviewedHost?.[1] !== host.ownerHmac || reviewJcs(reviewedTarget) !== reviewJcs([target.targetResourceHmac, target.dependentCount, target.dependencyFingerprint, target.fingerprintKeyId])) throw new Error('Reviewed target dependency snapshot changed');
  const snapshotHash = createHash('sha256').update(reviewJcs([1, rows])).digest('hex');
  const payload = [1, signer.writerId, signer.keyId, decision.decisionId, decision.jobId, decision.hostId, host.ownerHmac, target.targetResourceHmac, decision.disposition, decision.decisionMaker, decision.decidedAt, decision.reason, snapshotHash, rows, decision.expiresAt];
  const bytes = Buffer.from(reviewDecisionDomain + reviewJcs(payload), 'utf8');
  const signature = await signer.sign(bytes);
  if (signature.length !== 64) throw new Error('Invalid review signature');
  return { payload, signature: Buffer.from(signature).toString('base64url') };
}


type ReviewInput = Parameters<typeof signReviewDecision>[0];
export async function signResourceReviewDecision(decision: ReviewInput, snapshot: DeletionHostSnapshot, observations: ResourceDependencyObservation[], signer?: ReviewDecisionSigner): Promise<ReviewDecisionProof> {
  if (decision.decisionMaker === 'deadline') throw new Error('Deadline requires verified request and TEE clock');
  return signReviewDecision(decision, snapshot, observations, signer);
}

export interface DeadlineReviewAuthority extends ReviewDecisionSigner {
  // The TEE adapter verifies this ledger record; request time is never an input
  // to the exported signing operation.
  verifiedRequest(jobId: string): Promise<{ jobId: string; requestId: string; requestedAt: number; hosts: DeletionHostSnapshot; ownerHmacs: Record<string, string> }>;
  teeNow(): Promise<number>;
  deadlineRevoked(jobId: string): Promise<boolean>;
  // Atomic, durable one-per-job claim; false on any earlier attempt, including
  // an expired/revoked one. No automatic replacement authorization.
  claimDeadline(jobId: string, requestId: string, nonce: string): Promise<boolean>;
}

export async function signDeadlineReviewDecisions(jobId: string, snapshot: DeletionHostSnapshot, observations: ResourceDependencyObservation[], authority?: DeadlineReviewAuthority): Promise<ReviewDecisionProof[]> {
  if (!authority) throw new Error('Deadline signing authority unavailable');
  const request = await authority.verifiedRequest(jobId);
  const now = await authority.teeNow();
  if (!uuidPattern.test(jobId) || request.jobId !== jobId || !uuidPattern.test(request.requestId) || !Number.isSafeInteger(request.requestedAt) || request.requestedAt < 0 || !Number.isSafeInteger(now) || now < request.requestedAt + 604800) throw new Error('Deadline is not eligible');
  if (reviewJcs(request.hosts) !== reviewJcs(snapshot) || observations.some(row => request.ownerHmacs[row.hostId] !== row.ownerHmac)) throw new Error('Deadline request scope mismatch');
  buildReviewSnapshot(snapshot, observations);
  if (await authority.deadlineRevoked(jobId)) throw new Error('Deadline authorization revoked; operator escalation required');
  const nonce = crypto.randomUUID();
  if (!await authority.claimDeadline(jobId, request.requestId, nonce)) throw new Error('Deadline already attempted; operator escalation required');
  const proofs: ReviewDecisionProof[] = [];
  for (const host of observations) for (const target of host.targets) {
    proofs.push(await signReviewDecision({ jobId, decisionId: crypto.randomUUID(), hostId: host.hostId, resourceId: target.resourceId, disposition: 'proceed', decisionMaker: 'deadline', decidedAt: now, expiresAt: now + 172800, reason: 'Seven-day deletion review window elapsed; fresh dependency snapshot recorded' }, snapshot, observations, authority, now));
  }
  return proofs;
}
