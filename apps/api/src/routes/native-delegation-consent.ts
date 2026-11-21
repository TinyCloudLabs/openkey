import type { Hex } from 'viem';
import type { ReviewerBinding } from '../services/reviewer-accounts';
import { lockNativeReviewer, nativeReviewerAuthority } from '../services/reviewer-native';
import { recordReviewerWriter } from '../services/reviewer-cleanup';
import { sameTinyCloudHost } from '../services/tinycloud-hosts';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { Hono } from 'hono';
import { Prisma, type PrismaClient } from '@openkey/db';
import { ensureEip55, generateHostSIWEMessage, completeSessionSetup, siweToDelegationHeaders } from '@tinycloud/node-sdk-wasm';
import { activateSessionWithHost, submitHostDelegation } from '@tinycloud/sdk-core';
import { createWalletFromPrivateKey } from '@openkey/tee';
import type { SessionContext } from '../middleware/session';
import { auth } from '../auth';
import { isAccountOriginAllowed, resolveOriginPolicy } from '../origin-policy';
import { requireAccountOriginForBearer } from '../middleware/bearer-origin';
import { primaryKeyWhere } from '../services/primary-key';
import { signManagedKey, unsealManagedKey } from '../services/managed-key-signing';
import { nativeDelegationLockResponse } from '../services/native-delegation/errors';
import { enabledNativeDelegation } from '../services/native-delegation/policy';
import { nativeUserRetryAfter, type NativeUserAction } from '../services/native-delegation/user-rate-limit';
import { hasAcceptedTerms, termsRequired } from '../services/terms';
import { ParError, validatePermissions, type NativePermission } from '../services/native-delegation/par';
import { GRANT_CUTOFF_MS, StepUpEntryError, validateStepUpPermissions, type StepUpPermission } from '../services/native-delegation/step-up';
import { revokeDelegationOnNode, revokeOwnerDelegation, revokePendingRecord } from '../services/native-delegation/revoke-pending';
import { RECLAIM_FAILED_CODE } from '../services/tinycloud-bootstrap';
import { prepareDelegationSession, actionKey } from './delegate-session';
import { approvalPasskeyOfferInFlow, approvalRequestDigest, checkApprovalPasskeyInFlow, clearFlowPasskey, messageApprovalSensitivity, type ApprovalBinding, type ApprovalPasskeyMethod } from '../services/approval-passkey';

import { log, logError } from '../log';
export class NativeConsentError extends Error {
  constructor(readonly status: 401 | 403 | 404 | 409 | 500 | 503, readonly code: string, readonly description?: string) { super(code); }
}
function fail(status: NativeConsentError['status'], code: string): never { throw new NativeConsentError(status, code); }
const active = (row: { status: string; expiresAt: Date }) => {
  if (row.status !== 'RESOLVED' || row.expiresAt <= new Date()) fail(409, 'request_not_pending');
};
function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => [k, sorted(v)]));
  return value;
}
export function preparationDigest(preview: unknown): string {
  return createHash('sha256').update(JSON.stringify(sorted(preview))).digest('base64url');
}
export function sameApprovedSiwe(preview: string, rebuilt: string): boolean {
  const strip = (s: string) => s.split('\n').map(line => /^(Issued At|Expiration Time): /.test(line) ? line.slice(0, line.indexOf(':') + 1) : line).join('\n');
  return strip(preview) === strip(rebuilt);
}
function permitted(value: unknown, ceiling: Parameters<typeof validatePermissions>[1]): NativePermission[] {
  try { return validatePermissions(value, ceiling); }
  catch (error) { if (error instanceof ParError) fail(409, 'preparation_superseded'); throw error; }
}
function prepareSiwe(row: { sessionJwk: unknown }, permissions: Array<{ service: string; space: string; path: string; actions: string[] }>, key: { address: string }, ceiling: { siweDomain?: string }, nonce: string, ttlSeconds: number, at: Date) {
  return prepareDelegationSession({
    address: ensureEip55(key.address), chainId: 1, prefix: 'applications', jwk: row.sessionJwk as { kty: string; crv: string; x: string },
    permissions, expiryMs: ttlSeconds * 1000, domain: ceiling.siweDomain ?? 'openkey.so', nonce, issuedAt: at,
  });
}
function selectedPermissions(requested: NativePermission[], selection: unknown, spaceId: string): NativePermission[] {
  if (selection === undefined) return requested;
  if (!Array.isArray(selection) || selection.some(v => typeof v !== 'string') || new Set(selection).size !== selection.length) fail(409, 'preparation_mismatch');
  const all = new Set(requested.flatMap(p => p.actions.map(a => actionKey({ ...p, space: spaceId }, a))));
  const selected = selection as string[];
  if (selected.some(k => !all.has(k))) fail(409, 'preparation_mismatch');
  const wanted = new Set(selected);
  return requested.map(p => ({ ...p, actions: p.actions.filter(a => wanted.has(actionKey({ ...p, space: spaceId }, a)) || a === 'tinycloud.capabilities/read') })).filter(p => p.actions.length);
}
/** TC-3442: a passkey on a native approval confirms this request's revision and its prepared bytes. */
function nativePasskeyBinding(requestId: string, revision: number, digest: string): ApprovalBinding {
  return { purpose: 'native_consent', requestDigest: approvalRequestDigest(requestId, String(revision), digest) };
}
async function lockRequest(tx: any, id: string, userId: string, allowApproved = false) {
  await tx.$executeRawUnsafe("SET LOCAL lock_timeout = '5s'");
  const before = await tx.tinyCloudNativeRequest.findUnique({ where: { id } });
  if (!before) fail(404, 'request_not_found');
  await tx.$queryRawUnsafe('SELECT id FROM oauth_consent WHERE "userId" = $1 AND "clientId" = $2 FOR SHARE', userId, before.clientId);
  await tx.$executeRawUnsafe('INSERT INTO tinycloud_native_consent_generation ("userId", "clientId", generation) VALUES ($1, $2, 0) ON CONFLICT DO NOTHING', userId, before.clientId);
  const generation = await tx.$queryRawUnsafe('SELECT generation FROM tinycloud_native_consent_generation WHERE "userId" = $1 AND "clientId" = $2 FOR SHARE', userId, before.clientId) as { generation: bigint }[];
  await tx.$queryRawUnsafe('SELECT id FROM tinycloud_native_request WHERE id = $1 FOR UPDATE', id);
  const row = await tx.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } });
  if (!(allowApproved && row.status === 'APPROVED' && row.expiresAt > new Date())) active(row);
  if (row.userId && row.userId !== userId) fail(403, 'request_user_mismatch');
  return { row, generation: generation[0]!.generation };
}
interface ConsentKey { id: string; address: string; sealedBlob: string; userId: string | null; sealingContext: string | null }
async function keyFor(tx: any, userId: string): Promise<ConsentKey> {
  const key = await tx.ethereumKey.findFirst({ where: primaryKeyWhere(userId) });
  if (!key || !key.sealedBlob) fail(409, 'preparation_mismatch');
  return key as ConsentKey;
}
export interface NativeConsentHostOps {
  fetchPeerId: (host: string, spaceId: string) => Promise<string>;
  activateSessionWithHost: typeof activateSessionWithHost;
  submitHostDelegation: typeof submitHostDelegation;
  revokeDelegation: (host: string, headers: Record<string, string>) => Promise<{ ok: boolean; status: number }>;
}
async function fetchPeerId(host: string, spaceId: string): Promise<string> {
  const response = await fetch(`${host}/peer/generate/${encodeURIComponent(spaceId)}`, { signal: AbortSignal.timeout(5_000) });
  const value = (await response.text()).trim();
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${value.slice(0, 200)}`);
  if (!value.startsWith('did:key:')) throw new Error(`unexpected peer ID response: ${value.slice(0, 100)}`);
  return value;
}
class NativeOperationTimeoutError extends Error {
  constructor(ms: number) { super(`operation timed out after ${ms} ms`); this.name = 'NativeOperationTimeoutError'; }
}
async function withinTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new NativeOperationTimeoutError(ms)), ms); })]); }
  finally { if (timer) clearTimeout(timer); }
}
const defaultHostOps: NativeConsentHostOps = { fetchPeerId, activateSessionWithHost, submitHostDelegation, revokeDelegation: revokeDelegationOnNode };
export function createNativeDelegationConsentRouter(db: PrismaClient, hostOps: NativeConsentHostOps = defaultHostOps) {
  const router = new Hono<SessionContext>();
  router.use('*', async (c, next) => {
    const origin = c.req.header('origin');
    if (!origin || !resolveOriginPolicy('http://localhost:5173').includes(origin)) return c.json({ error: 'invalid_origin' }, 403);
    if (c.req.header('authorization')) return c.json({ error: 'unauthorized' }, 401);
    await next();
  });
  const requireAccountOrigin = createMiddleware(async (c, next) => {
    if (!isAccountOriginAllowed(c.req.header('origin'), 'http://localhost:5173')) return c.json({ error: 'invalid_origin' }, 403);
    await next();
  });
  router.use('/:id/prepare', requireAccountOrigin);
  router.use('/:id/deny', requireAccountOriginForBearer);
  router.use('/:id/approve', requireAccountOrigin);
  router.use('*', async (c, next) => {
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    if (!session) return c.json({ error: 'unauthorized' }, 401);
    // TC-3232: no new grant is prepared or approved until the account accepts the Terms. Denying stays open.
    const action = c.req.path.split('/').at(-1);
    if ((action === 'prepare' || action === 'approve') && !await hasAcceptedTerms(db, session.user.id)) {
      return c.json(termsRequired(), 403);
    }
    c.set('user', session.user);
    c.set('session', session.session);
    await next();
  });
  router.use('*', async (c, next) => {
    const action = c.req.path.split('/').at(-1);
    if (action === 'prepare' || action === 'approve' || action === 'deny') {
      const retryAfter = nativeUserRetryAfter(c.get('user').id, action as NativeUserAction);
      if (retryAfter) return c.json({ error: 'slow_down' }, 429, { 'Retry-After': String(retryAfter), 'Cache-Control': 'no-store' });
    }
    await next();
  });
  router.onError((error, c) => {
    if (error instanceof NativeConsentError) return c.json({ error: error.code, ...(error.description ? { error_description: error.description } : {}) }, error.status, error.status === 503 ? { 'Retry-After': '2' } : undefined);
    const lockResponse = nativeDelegationLockResponse(error);
    if (lockResponse) return lockResponse;
    throw error;
  });
  router.post('/:id/prepare', async (c) => {
    const body = await c.req.json().catch(() => ({})) as { actionKeys?: unknown };
    const userId = c.get('user').id;
    // Peer lookup is network I/O. Decide whether it is needed before taking
    // the consent/generation/request locks, then recheck the host under lock.
    const pending = await db.tinyCloudNativeRequest.findUnique({ where: { id: c.req.param('id') } });
    if (!pending) fail(404, 'request_not_found');
    // A step-up is consented by its own gate; any other kind is refused.
    if (pending.kind === 'STEPUP') return c.json(await prepareStepUp(userId, c.get('session')?.id ?? null, pending.id));
    if (pending.kind !== 'SIGNIN') fail(409, 'unsupported_request_kind');
    const preReviewer = await nativeReviewerAuthority(db, userId, pending);
    if (pending.userId && pending.userId !== userId) fail(403, 'request_user_mismatch');
    if (pending.status === 'APPROVED' && pending.userId === userId && pending.expiresAt > new Date()) {
      return c.json({ status: 'APPROVED' });
    }
    active(pending);
    const preKey = await keyFor(db, userId);
    const preClient = await db.oauthClient.findUniqueOrThrow({ where: { clientId: pending.clientId } });
    const preCeiling = enabledNativeDelegation(preClient);
    if (!preCeiling) fail(409, 'preparation_superseded');
    const preExisting = await db.tinyCloudBootstrapState.findFirst({ where: { keyId: preKey.id, chainId: 1, tinycloudHost: preCeiling.tinycloudHost, status: 'complete' } });
    const preSpace = prepareSiwe(pending, permitted(pending.requestedPermissions, preCeiling), preKey, preCeiling,
      pending.siweNonce ?? 'AAAAAAAAAAAA', Math.min(pending.ttlSeconds, preCeiling.maxDelegationTtlSeconds, preCeiling.grantLifetimeSeconds), new Date()).spaceId;
    if (preReviewer && (!preExisting || preKey.id !== preReviewer.binding.keyId || preSpace !== preReviewer.binding.spaceId
      || preCeiling.tinycloudHost !== preReviewer.binding.nodeHost)) fail(403, 'reviewer_host_required');
    let peerId: string | null = null;
    if (!preExisting) {
      try { peerId = await withinTimeout(hostOps.fetchPeerId(preCeiling.tinycloudHost, preSpace), 5_000); }
      catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        logError('error', 'native_consent_peer_lookup_failed', error);
        throw new NativeConsentError(503, 'temporarily_unavailable', `TinyCloud node peer lookup failed: ${reason.slice(0, 200)}`);
      }
    }
    const result = await db.$transaction(async tx => {
      const reviewerBinding = await lockNativeReviewer(tx, userId);
      const { row } = await lockRequest(tx, c.req.param('id'), userId);
      const reviewer = await nativeReviewerAuthority(tx, userId, row, reviewerBinding);
      const key = await keyFor(tx, userId);
      if (reviewer && key.id !== reviewer.binding.keyId) fail(403, 'reviewer_key_mismatch');
      const client = await tx.oauthClient.findUniqueOrThrow({ where: { clientId: row.clientId }, include: { organization: { select: { name: true } } } });
      const ceiling = enabledNativeDelegation(client);
      if (!ceiling) fail(409, 'preparation_superseded');
      if (!sameTinyCloudHost(ceiling.tinycloudHost, preCeiling.tinycloudHost) || key.id !== preKey.id) fail(409, 'preparation_superseded');
      const requested = permitted(row.requestedPermissions, ceiling);
      const preparedAt = new Date();
      const ttlSeconds = Math.min(row.ttlSeconds, ceiling.maxDelegationTtlSeconds, ceiling.grantLifetimeSeconds, reviewer ? Math.floor((reviewer.deadline - preparedAt.getTime()) / 1000) : Infinity);
      if (ttlSeconds < 1) fail(403, 'reviewer_session_ended');
      const nonce = row.siweNonce ?? randomBytes(12).toString('base64url').replaceAll('-', 'A').replaceAll('_', 'B');
      const address = ensureEip55(key.address);
      const base = prepareSiwe(row, requested, key, ceiling, nonce, ttlSeconds, preparedAt);
      const permissions = selectedPermissions(requested, body.actionKeys, base.spaceId);
      const prepared = prepareSiwe(row, permissions, key, ceiling, nonce, ttlSeconds, preparedAt);
      const existing = await tx.tinyCloudBootstrapState.findFirst({ where: { keyId: key.id, chainId: 1, tinycloudHost: ceiling.tinycloudHost, status: 'complete' } });
      if (reviewer && (!existing || prepared.spaceId !== reviewer.binding.spaceId || ceiling.tinycloudHost !== reviewer.binding.nodeHost)) fail(403, 'reviewer_host_required');
      let hostPlan: { host: string; spaceId: string; peerId: string; hostSiwe: string } | null = null;
      if (!existing) {
        if (!peerId || prepared.spaceId !== preSpace) fail(409, 'preparation_superseded');
        hostPlan = { host: ceiling.tinycloudHost, spaceId: prepared.spaceId, peerId,
          hostSiwe: generateHostSIWEMessage({ address, chainId: 1, domain: ceiling.siweDomain ?? 'openkey.so', issuedAt: new Date().toISOString(), spaceId: prepared.spaceId, peerId }) };
      }
      const revision = row.currentRevision + 1;
      const preview = { requestId: row.id, revision, userId, keyId: key.id, address, sessionSiwe: prepared.prepared.siwe, permissions, hostPlan };
      const digest = preparationDigest(preview);
      await tx.tinyCloudNativePreparation.create({ data: { id: randomUUID(), requestId: row.id, revision, userId, keyId: key.id, address, tinycloudHost: ceiling.tinycloudHost, sessionSiwe: preview.sessionSiwe, permissions, hostPlan: hostPlan ?? undefined, digest } });
      await tx.tinyCloudNativeRequest.update({ where: { id: row.id }, data: { userId, siweNonce: nonce, currentRevision: revision, ...(reviewer ? { reviewerEpoch: reviewer.binding.installEpoch, reviewerSessionId: reviewer.sessionId, reviewerDeadline: new Date(reviewer.deadline) } : {}) } });
      return { ...preview, digest, kind: 'SIGNIN' as const, client: { clientId: client.clientId, name: client.name, icon: client.icon, organization: client.organization?.name }, redirectScheme: new URL(row.redirectUri).protocol.slice(0, -1), sessionDid: row.sessionDid, tinycloudHost: ceiling.tinycloudHost, ttlSeconds, grantLifetimeSeconds: reviewer ? reviewer.ttlSeconds : ceiling.grantLifetimeSeconds, permissionOptions: prepared.permissions, selectedActionKeys: prepared.selectedActionKeys };
    }, { timeout: 15_000 });
    // TC-3442: whether Approve needs the passkey, with the challenge for this revision. TC-3596: none when the passkey
    // sign-in made for this request already covers it.
    const passkey = await approvalPasskeyOfferInFlow(db, { userId, sessionId: c.get('session')?.id ?? null },
      nativePasskeyBinding(result.requestId, result.revision, result.digest), messageApprovalSensitivity(result.sessionSiwe, result.address), result.requestId);
    return c.json({ ...result, passkey });
  });
  // The node registered the skipped session delegation although the approval is being reopened. Revoke it,
  // once and best-effort: the outcome never changes the restart.
  async function revokeStaleSessionDelegation(artifact: { address: string; delegationCid: string; tinycloudHost: string }, domain: string, privateKey: `0x${string}`): Promise<boolean> {
    return revokeOwnerDelegation(artifact, domain, (message) => createWalletFromPrivateKey(privateKey).signMessage({ message }), hostOps);
  }
  router.post('/:id/approve', async c => {
    const body = await c.req.json().catch(() => null) as { revision?: number; digest?: string; sessionSiwe?: string; hostSiwe?: string; passkeyAssertion?: unknown } | null;
    const userId = c.get('user').id;
    const pending = await db.tinyCloudNativeRequest.findUnique({ where: { id: c.req.param('id') } });
    if (!pending) fail(404, 'request_not_found');
    // A step-up is consented by its own gate; any other kind is refused.
    if (pending.kind !== 'SIGNIN' && pending.kind !== 'STEPUP') fail(409, 'unsupported_request_kind');
    const preReviewer = await nativeReviewerAuthority(db, userId, pending);
    if (pending.userId && pending.userId !== userId) fail(403, 'request_user_mismatch');
    if (pending.status !== 'APPROVED') active(pending);
    if (pending.expiresAt <= new Date()) fail(409, 'request_not_pending');
    if (!body || body.revision !== pending.currentRevision) fail(409, 'preparation_superseded');
    const preRevision = await db.tinyCloudNativePreparation.findUnique({ where: { requestId_revision: { requestId: pending.id, revision: body.revision } } });
    if (!preRevision || preRevision.digest !== body.digest || preRevision.sessionSiwe !== body.sessionSiwe ||
      ((preRevision.hostPlan as { hostSiwe?: string } | null)?.hostSiwe ?? undefined) !== body.hostSiwe) fail(409, 'preparation_mismatch');
    // TC-3442: the account's passkey setting, before the key is unsealed. A replay of an approved revision signs nothing.
    // TC-3596: a passkey sign-in made for this very request counts as the approval's passkey; the method is recorded.
    let passkeyMethod: ApprovalPasskeyMethod = 'NOT_REQUIRED';
    if (pending.status !== 'APPROVED') {
      const gate = await checkApprovalPasskeyInFlow(db, { userId, sessionId: c.get('session')?.id ?? null },
        nativePasskeyBinding(pending.id, preRevision.revision, preRevision.digest),
        messageApprovalSensitivity(preRevision.sessionSiwe, preRevision.address), body.passkeyAssertion, pending.id);
      if (gate.refusal) return c.json(gate.refusal, 403);
      passkeyMethod = gate.method;
    }
    // TEE key derivation can perform I/O. Unseal before the database locks;
    // the canonical key and approved bytes are checked again under the lock.
    const preKey = pending.status === 'APPROVED' ? null : await keyFor(db, userId);
    let privateKey: Awaited<ReturnType<typeof unsealManagedKey>> | null = null;
    if (preKey) {
      try { privateKey = await withinTimeout(unsealManagedKey(preKey, preKey.sealedBlob), 5_000); }
      catch (error) {
        // The blob and TEE error text may contain sensitive material. Log only
        // the error kind; a corrupt blob or sealing-context mismatch is not a
        // transient outage and must not receive Retry-After.
        logError('error', 'native_consent_key_unseal_failed', error);
        if (error instanceof NativeOperationTimeoutError) fail(503, 'temporarily_unavailable');
        fail(500, 'key_unavailable');
      }
    }
    if (pending.kind === 'STEPUP') {
      if (!body) fail(409, 'preparation_superseded');
      const stepUp = await approveStepUp(userId, pending.id, body, preKey, privateKey, passkeyMethod);
      await clearFlowPasskey(db, pending.id);
      return c.json(stepUp);
    }
    const result = await db.$transaction(async tx => {
      const reviewerBinding = await lockNativeReviewer(tx, userId);
      const { row, generation } = await lockRequest(tx, c.req.param('id'), userId, true);
      if (row.userId !== userId) fail(403, 'request_user_mismatch');
      if (!body || body.revision !== row.currentRevision) fail(409, 'preparation_superseded');
      const revision = await tx.tinyCloudNativePreparation.findUnique({ where: { requestId_revision: { requestId: row.id, revision: body.revision! } } });
      if (!revision || revision.digest !== body.digest || revision.sessionSiwe !== body.sessionSiwe) fail(409, 'preparation_mismatch');
      const hostPlan = revision.hostPlan as { host: string; spaceId: string; peerId: string; hostSiwe: string } | null;
      if ((hostPlan?.hostSiwe ?? undefined) !== body.hostSiwe) fail(409, 'preparation_mismatch');
      if (row.status === 'APPROVED') {
        await nativeReviewerAuthority(tx, userId, row, reviewerBinding);
        if (row.approvedRevision !== revision.revision) fail(409, 'request_not_pending');
        return { alreadyApproved: true as const, rowId: row.id, revision: revision.revision, hosting: row.hosting };
      }
      const reviewer = await nativeReviewerAuthority(tx, userId, row, reviewerBinding);
      const key = await keyFor(tx, userId);
      if (reviewer && key.id !== reviewer.binding.keyId) fail(403, 'reviewer_key_mismatch');
      if (key.id !== revision.keyId || key.id !== preKey?.id || key.sealedBlob !== preKey.sealedBlob ||
        ensureEip55(key.address) !== revision.address) fail(409, 'preparation_mismatch');
      const client = await tx.oauthClient.findUniqueOrThrow({ where: { clientId: row.clientId } });
      const ceiling = enabledNativeDelegation(client);
      if (!ceiling || revision.permissions == null) fail(409, 'preparation_superseded');
      if (!sameTinyCloudHost(revision.tinycloudHost, ceiling.tinycloudHost)) fail(409, 'preparation_superseded');
      const permissions = permitted(revision.permissions, ceiling);
      const ttl = Math.min(ceiling.maxDelegationTtlSeconds, ceiling.grantLifetimeSeconds);
      const timestamps = /Issued At: ([^\n]+)\nExpiration Time: ([^\n]+)/.exec(revision.sessionSiwe);
      const revisionTtl = timestamps ? (Date.parse(timestamps[2]!) - Date.parse(timestamps[1]!)) / 1000 : NaN;
      if (!Number.isInteger(revisionTtl) || revisionTtl > ttl) fail(409, 'preparation_superseded');
      if (!row.siweNonce) fail(409, 'preparation_mismatch');
      const signedAt = new Date();
      const signedTtl = Math.min(revisionTtl, reviewer ? Math.floor((reviewer.deadline - signedAt.getTime()) / 1000) : Infinity);
      if (signedTtl < 1) fail(403, 'reviewer_session_ended');
      if (reviewer && (hostPlan || revision.tinycloudHost !== reviewer.binding.nodeHost)) fail(403, 'reviewer_host_required');
      const rebuilt = prepareSiwe(row, permissions, key, ceiling, row.siweNonce, signedTtl, signedAt);
      if (!sameApprovedSiwe(revision.sessionSiwe, rebuilt.prepared.siwe)) fail(409, 'preparation_mismatch');
      const signature = await createWalletFromPrivateKey(privateKey!).signMessage({ message: rebuilt.prepared.siwe });
      const delegation = completeSessionSetup({ ...rebuilt.prepared, signature });
      const artifact = { version: 1, address: revision.address, chainId: 1, ownerDid: `did:pkh:eip155:1:${revision.address}`,
        sessionDid: row.sessionDid, sessionJkt: row.sessionJkt, issuedAt: signedAt.toISOString(),
        expiresAt: new Date(signedAt.getTime() + signedTtl * 1000).toISOString(), siwe: rebuilt.prepared.siwe,
        signature, delegationHeader: delegation.delegationHeader, delegationCid: delegation.delegationCid,
        spaceId: delegation.spaceId, verificationMethod: delegation.verificationMethod, permissions,
        ttlSeconds: signedTtl, tinycloudHost: ceiling.tinycloudHost };
      if (reviewer) await recordReviewerWriter(tx, reviewer.binding, new Date(artifact.expiresAt));
      await tx.tinyCloudNativeRequest.update({ where: { id: row.id }, data: { status: 'APPROVED', approvedRevision: revision.revision, consentGeneration: generation, signature, delegation: artifact, hosting: 'failed', approvalPasskeyMethod: passkeyMethod } });
      return { alreadyApproved: false as const, rowId: row.id, revision: revision.revision, hostPlan, artifact, key, siweDomain: ceiling.siweDomain ?? 'openkey.so' };
    }, { timeout: 15_000 });
    await clearFlowPasskey(db, pending.id);
    if (result.alreadyApproved) return c.json({ status: 'APPROVED', revision: result.revision, hosting: result.hosting });
    let hosting: 'existing' | 'created' | 'failed' = 'failed';
    let restart = false;
    try {
      const activated = await hostOps.activateSessionWithHost(result.artifact.tinycloudHost, result.artifact.delegationHeader);
      if (activated.success && activated.activated?.includes(result.artifact.spaceId)) hosting = 'existing';
      else if (result.hostPlan && activated.skipped?.includes(result.artifact.spaceId)) {
        const marked = await db.tinyCloudNativeRequest.updateMany({ where: { id: result.rowId, hostSignedAt: null }, data: { hostSignedAt: new Date() } });
        if (marked.count === 1) {
          const signature = await signManagedKey(result.key, result.key.sealedBlob, result.hostPlan.hostSiwe);
          const submitted = await hostOps.submitHostDelegation(result.hostPlan.host, siweToDelegationHeaders({ siwe: result.hostPlan.hostSiwe, signature }) as Record<string, string>);
          if (submitted.success) {
            const retry = await hostOps.activateSessionWithHost(result.artifact.tinycloudHost, result.artifact.delegationHeader);
            // N2 persists the first (skipped) delegation globally. Once the
            // host SIWE creates the space, resubmitting those same bytes is
            // idempotent: HTTP 200 with both lists empty.
            const alreadyRegistered = retry.activated?.length === 0 && retry.skipped?.length === 0;
            if (retry.success && (retry.activated?.includes(result.artifact.spaceId) || alreadyRegistered)) hosting = 'created';
            else log('warn', 'native_consent_activation_after_host_setup_failed');
          }
          else log('warn', 'native_consent_host_delegation_rejected');
        }
      }
      else if (!result.hostPlan && activated.skipped?.includes(result.artifact.spaceId)) {
        // The cached `complete` row was stale, so no hosting plan was shown or signed. Drop the cached bit and
        // reopen the request on a new revision, so a replay of this approval is superseded: the next prepare plans hosting and shows it. The row is no longer `complete`, so
        // that prepare always carries a plan and this branch cannot run for it again.
        restart = await db.$transaction(async tx => {
          const stale = await tx.tinyCloudBootstrapState.updateMany({
            where: { keyId: result.key.id, chainId: 1, tinycloudHost: result.artifact.tinycloudHost, status: 'complete' },
            data: { status: 'failed', failureCode: RECLAIM_FAILED_CODE, failureReason: 'TinyCloud node does not host the applications space.', attemptId: null, lockExpiresAt: null },
          });
          if (stale.count === 0) return false;
          const reopened = await tx.tinyCloudNativeRequest.updateMany({
            where: { id: result.rowId, status: 'APPROVED', approvedRevision: result.revision, currentRevision: result.revision, hostSignedAt: null },
            data: { status: 'RESOLVED', currentRevision: { increment: 1 }, approvedRevision: null, consentGeneration: null, signature: null, delegation: Prisma.DbNull, hosting: null },
          });
          if (reopened.count !== 1) throw new Error('native request could not be reopened');
          return true;
        });
        if (restart) await revokeStaleSessionDelegation(result.artifact, result.siweDomain, privateKey!);
        else log('warn', 'native_consent_activation_did_not_host_space');
      }
      else log('warn', 'native_consent_activation_did_not_host_space');
    } catch (error) {
      logError('warn', 'native_consent_host_activation_failed', error);
    }
    if (restart) fail(409, 'preparation_superseded');
    await db.tinyCloudNativeRequest.update({ where: { id: result.rowId }, data: { hosting } });
    return c.json({ status: 'APPROVED', revision: result.revision, hosting });
  });
  /**
   * TC-3569: what a step-up consent re-checks under the locks, for prepare and approve alike. The grant must
   * be live and unexpired, the account usable, the grant's key still the canonical one, the client's ceiling
   * must still cover every entry, and every requested space must already be hosted (bootstrap complete):
   * a step-up never hosts a space.
   */
  async function stepUpGate(tx: any, row: any, userId: string, generation: bigint, reviewerBinding: ReviewerBinding | null) {
    if (row.kind !== 'STEPUP' || !row.grantId || !row.appId) fail(409, 'unsupported_request_kind');
    if (await nativeReviewerAuthority(tx, userId, row, reviewerBinding)) fail(403, 'reviewer_stepup_refused');
    await tx.$queryRawUnsafe('SELECT id FROM tinycloud_native_grant WHERE id = $1 FOR SHARE', row.grantId);
    const grant = await tx.tinyCloudNativeGrant.findUnique({ where: { id: row.grantId } });
    const now = Date.now();
    // Same live and expiry rule as renewal: an expired grant keeps the status ACTIVE.
    if (!grant || grant.status !== 'ACTIVE' || grant.userId !== userId || grant.clientId !== row.clientId || grant.consentGeneration !== generation ||
      grant.sessionJkt !== row.sessionJkt || grant.sessionDid !== row.sessionDid || now >= grant.absoluteExpiresAt.getTime() - GRANT_CUTOFF_MS) fail(409, 'preparation_superseded');
    const user = await tx.user.findUnique({ where: { id: userId }, select: { lockedAt: true, reviewerHoldAt: true, tinyCloudManageKeyMode: true } });
    if (!user || user.lockedAt || user.reviewerHoldAt) fail(403, 'access_denied');
    // The request was made under the consent generation the grant carries; withdrawing consent bumps it.
    if (row.consentGeneration != null && row.consentGeneration !== generation) fail(409, 'preparation_superseded');
    // The grant's refresh token must still be its live one (a sign-out or revoke ends the step-up with it).
    await tx.$queryRawUnsafe('SELECT id FROM oauth_refresh_token WHERE token = $1 FOR SHARE', grant.refreshTokenHash);
    const token = await tx.oauthRefreshToken.findUnique({ where: { token: grant.refreshTokenHash } });
    if (!token || token.userId !== userId || token.clientId !== grant.clientId || token.revoked || token.expiresAt.getTime() <= now) fail(409, 'preparation_superseded');
    const preference = await tx.tinyCloudManageKeyAppPreference.findUnique({ where: { userId_clientId: { userId, clientId: grant.clientId } } });
    if (user.tinyCloudManageKeyMode === 'USER_CONTROLLED_EXCLUSIVE' || preference?.status === 'DISABLED' || preference?.enabled === false) fail(403, 'access_denied');
    const key = await keyFor(tx, userId);
    if (key.id !== grant.keyId || ensureEip55(key.address) !== ensureEip55(grant.address)) fail(409, 'preparation_mismatch');
    const client = await tx.oauthClient.findUniqueOrThrow({ where: { clientId: row.clientId }, include: { organization: { select: { name: true } } } });
    const ceiling = enabledNativeDelegation(client);
    if (!ceiling || !sameTinyCloudHost(ceiling.tinycloudHost, grant.tinycloudHost)) fail(409, 'preparation_superseded');
    let permissions: StepUpPermission[];
    try { permissions = validateStepUpPermissions(row.appId, row.requestedPermissions, ceiling.stepUps); }
    catch (error) { if (error instanceof StepUpEntryError) fail(409, 'preparation_superseded'); throw error; }
    const hosted = await tx.tinyCloudBootstrapState.findFirst({ where: { keyId: key.id, chainId: 1, tinycloudHost: ceiling.tinycloudHost, status: 'complete' } });
    if (!hosted) throw new NativeConsentError(409, 'space_not_hosted', `Spaces not hosted on this node: ${[...new Set(permissions.map(p => p.space))].join(', ')}`);
    const maxTtl = Math.min(row.ttlSeconds, ceiling.maxDelegationTtlSeconds);
    return { grant, key, client, ceiling, permissions, maxTtl, remainingSeconds: (at: Date) => Math.floor((grant.absoluteExpiresAt.getTime() - at.getTime()) / 1000) };
  }
  async function prepareStepUp(userId: string, sessionId: string | null, requestId: string) {
    const result = await db.$transaction(async tx => {
      const reviewerBinding = await lockNativeReviewer(tx, userId);
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR SHARE`;
      const { row, generation } = await lockRequest(tx, requestId, userId);
      const gate = await stepUpGate(tx, row, userId, generation, reviewerBinding);
      const preparedAt = new Date();
      // The delegation never outlives the grant it is bound to.
      const ttlSeconds = Math.min(gate.maxTtl, gate.remainingSeconds(preparedAt));
      if (ttlSeconds < 1) fail(409, 'preparation_superseded');
      const nonce = row.siweNonce ?? randomBytes(12).toString('base64url').replaceAll('-', 'A').replaceAll('_', 'B');
      const address = ensureEip55(gate.key.address);
      const prepared = prepareSiwe(row, gate.permissions, gate.key, gate.ceiling, nonce, ttlSeconds, preparedAt);
      const revision = row.currentRevision + 1;
      const preview = { requestId: row.id, revision, userId, keyId: gate.key.id, address, sessionSiwe: prepared.prepared.siwe, permissions: gate.permissions, hostPlan: null,
        stepUp: { grantId: gate.grant.id, appId: row.appId as string } };
      const digest = preparationDigest(preview);
      await tx.tinyCloudNativePreparation.create({ data: { id: randomUUID(), requestId: row.id, revision, userId, keyId: gate.key.id, address, tinycloudHost: gate.ceiling.tinycloudHost, sessionSiwe: preview.sessionSiwe, permissions: gate.permissions, digest } });
      await tx.tinyCloudNativeRequest.update({ where: { id: row.id }, data: { userId, siweNonce: nonce, currentRevision: revision } });
      // Read-only: a revoked step-up is only ever re-activated by the exchange of an approved request.
      const existing = await tx.tinyCloudNativeStepUp.findUnique({ where: { grantId_appId: { grantId: gate.grant.id, appId: row.appId } } });
      return { ...preview, digest, kind: 'STEPUP' as const, reactivation: existing?.status === 'REVOKED',
        client: { clientId: gate.client.clientId, name: gate.client.name, icon: gate.client.icon, organization: gate.client.organization?.name },
        redirectScheme: new URL(row.redirectUri).protocol.slice(0, -1), sessionDid: row.sessionDid, tinycloudHost: gate.ceiling.tinycloudHost, ttlSeconds,
        grantLifetimeSeconds: gate.remainingSeconds(preparedAt), spaces: prepared.requestedSpaces, permissionOptions: prepared.permissions, selectedActionKeys: prepared.selectedActionKeys };
    }, { timeout: 15_000 });
    const passkey = await approvalPasskeyOfferInFlow(db, { userId, sessionId },
      nativePasskeyBinding(result.requestId, result.revision, result.digest), messageApprovalSensitivity(result.sessionSiwe, result.address), result.requestId);
    return { ...result, passkey };
  }
  async function approveStepUp(userId: string, requestId: string, body: { revision?: number; digest?: string; sessionSiwe?: string },
    preKey: ConsentKey | null, privateKey: Hex | null, passkeyMethod: ApprovalPasskeyMethod) {
    const result = await db.$transaction(async tx => {
      const reviewerBinding = await lockNativeReviewer(tx, userId);
      // A concurrent switch to user-controlled keys takes this row FOR UPDATE; it cannot land after the gate.
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR SHARE`;
      const { row, generation } = await lockRequest(tx, requestId, userId, true);
      if (row.userId !== userId) fail(403, 'request_user_mismatch');
      if (body.revision !== row.currentRevision) fail(409, 'preparation_superseded');
      const revision = await tx.tinyCloudNativePreparation.findUnique({ where: { requestId_revision: { requestId: row.id, revision: body.revision! } } });
      if (!revision || revision.digest !== body.digest || revision.sessionSiwe !== body.sessionSiwe || revision.hostPlan != null) fail(409, 'preparation_mismatch');
      if (row.status === 'APPROVED') {
        if (row.approvedRevision !== revision.revision) fail(409, 'request_not_pending');
        return { replay: true as const, revision: revision.revision, hosting: row.hosting };
      }
      const gate = await stepUpGate(tx, row, userId, generation, reviewerBinding);
      if (!preKey || !privateKey || gate.key.id !== revision.keyId || gate.key.id !== preKey.id || gate.key.sealedBlob !== preKey.sealedBlob ||
        ensureEip55(gate.key.address) !== revision.address) fail(409, 'preparation_mismatch');
      if (!sameTinyCloudHost(revision.tinycloudHost, gate.ceiling.tinycloudHost)) fail(409, 'preparation_superseded');
      const timestamps = /Issued At: ([^\n]+)\nExpiration Time: ([^\n]+)/.exec(revision.sessionSiwe);
      const revisionTtl = timestamps ? (Date.parse(timestamps[2]!) - Date.parse(timestamps[1]!)) / 1000 : NaN;
      if (!Number.isInteger(revisionTtl) || revisionTtl > gate.maxTtl) fail(409, 'preparation_superseded');
      if (!row.siweNonce) fail(409, 'preparation_mismatch');
      const signedAt = new Date();
      const signedTtl = Math.min(revisionTtl, gate.remainingSeconds(signedAt));
      if (signedTtl < 1) fail(409, 'preparation_superseded');
      const rebuilt = prepareSiwe(row, gate.permissions, gate.key, gate.ceiling, row.siweNonce, signedTtl, signedAt);
      if (!sameApprovedSiwe(revision.sessionSiwe, rebuilt.prepared.siwe)) fail(409, 'preparation_mismatch');
      const signature = await createWalletFromPrivateKey(privateKey).signMessage({ message: rebuilt.prepared.siwe });
      const delegation = completeSessionSetup({ ...rebuilt.prepared, signature });
      const spaces = rebuilt.requestedSpaces;
      const artifact = { version: 1, address: revision.address, chainId: 1, ownerDid: `did:pkh:eip155:1:${revision.address}`,
        sessionDid: row.sessionDid, sessionJkt: row.sessionJkt, issuedAt: signedAt.toISOString(),
        expiresAt: new Date(signedAt.getTime() + signedTtl * 1000).toISOString(), siwe: rebuilt.prepared.siwe,
        signature, delegationHeader: delegation.delegationHeader, delegationCid: delegation.delegationCid,
        spaceId: delegation.spaceId, verificationMethod: delegation.verificationMethod, permissions: gate.permissions,
        ttlSeconds: signedTtl, tinycloudHost: gate.ceiling.tinycloudHost, grantId: gate.grant.id, appId: row.appId as string };
      await tx.tinyCloudNativeRequest.update({ where: { id: row.id }, data: { status: 'APPROVED', approvedRevision: revision.revision, consentGeneration: generation, signature, delegation: artifact, hosting: 'failed', approvalPasskeyMethod: passkeyMethod } });
      return { replay: false as const, rowId: row.id, revision: revision.revision, artifact, spaces, siweDomain: gate.ceiling.siweDomain ?? 'openkey.so' };
    }, { timeout: 15_000 });
    if (result.replay) return { status: 'APPROVED' as const, revision: result.revision, hosting: result.hosting };
    // Every requested space must be hosted already. The activation receipt is the node's own answer, so a
    // space it skipped is refused: the approval is withdrawn and the delegation revoked on the node, and a
    // step-up never creates a space.
    let activated: string[] | null = null;
    try {
      // A node that does not answer must not hold the approval open: it fails like any activation failure.
      const activation = await hostOps.activateSessionWithHost(result.artifact.tinycloudHost, result.artifact.delegationHeader, AbortSignal.timeout(10_000));
      if (activation.success) activated = activation.activated ?? [];
    } catch (error) { logError('warn', 'native_consent_host_activation_failed', error); }
    const unhosted = result.spaces.filter(space => !activated?.includes(space.spaceId));
    if (activated && unhosted.length === 0) {
      await db.tinyCloudNativeRequest.update({ where: { id: result.rowId }, data: { hosting: 'existing' } });
      return { status: 'APPROVED' as const, revision: result.revision, hosting: 'existing' as const, spaces: result.spaces.map(space => space.space) };
    }
    // The approval is withdrawn at once. Until the node confirms the revoke, the request keeps a durable record
    // of the delegation's CID (an identifier, not authority: no signature, no header). The revoke sweep
    // (`revoke-pending.ts`) retries it until the node confirms or the delegation expires. It is never returned
    // to the client.
    const record = revokePendingRecord(result.artifact, result.siweDomain);
    await db.tinyCloudNativeRequest.updateMany({ where: { id: result.rowId, status: 'APPROVED', approvedRevision: result.revision },
      data: { status: 'DENIED', hosting: 'failed', signature: null, delegation: record } });
    if (await revokeStaleSessionDelegation(result.artifact, result.siweDomain, privateKey!)) {
      await db.tinyCloudNativeRequest.updateMany({ where: { id: result.rowId, status: 'DENIED' }, data: { delegation: Prisma.DbNull } });
    }
    if (!activated) fail(503, 'temporarily_unavailable');
    throw new NativeConsentError(409, 'space_not_hosted', `Spaces not hosted on this node: ${unhosted.map(space => space.space).join(', ')}`);
  }
  router.post('/:id/deny', async c => {
    const userId = c.get('user').id;
    await db.$transaction(async tx => {
      const reviewerBinding = await lockNativeReviewer(tx, userId);
      const { row } = await lockRequest(tx, c.req.param('id'), userId);
      await nativeReviewerAuthority(tx, userId, row, reviewerBinding);
      await tx.tinyCloudNativeRequest.update({ where: { id: row.id }, data: { status: 'DENIED' } });
    });
    await clearFlowPasskey(db, c.req.param('id'));
    return c.json({ status: 'DENIED' });
  });
  return router;
}
