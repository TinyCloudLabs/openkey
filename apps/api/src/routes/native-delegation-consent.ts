import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Hono } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { ensureEip55, generateHostSIWEMessage, completeSessionSetup, siweToDelegationHeaders } from '@tinycloud/node-sdk-wasm';
import { activateSessionWithHost, fetchPeerId, submitHostDelegation } from '@tinycloud/sdk-core';
import type { SessionContext } from '../middleware/session';
import { auth } from '../auth';
import { resolveOriginPolicy } from '../origin-policy';
import { primaryKeyWhere } from '../services/primary-key';
import { signManagedKey } from '../services/managed-key-signing';
import { enabledNativeDelegation } from '../services/native-delegation/policy';
import { ParError, validatePermissions, type NativePermission } from '../services/native-delegation/par';
import { prepareDelegationSession, actionKey } from './delegate-session';

export class NativeConsentError extends Error {
  constructor(readonly status: 401 | 403 | 404 | 409 | 503, readonly code: string) { super(code); }
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
function prepareSiwe(row: { sessionJwk: unknown }, permissions: NativePermission[], key: { address: string }, ceiling: { siweDomain?: string }, nonce: string, ttlSeconds: number, at: Date) {
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
async function lockRequest(tx: any, id: string, userId: string) {
  await tx.$executeRawUnsafe("SET LOCAL lock_timeout = '5s'");
  const before = await tx.tinyCloudNativeRequest.findUnique({ where: { id } });
  if (!before) fail(404, 'request_not_found');
  await tx.$queryRawUnsafe('SELECT id FROM oauth_consent WHERE "userId" = $1 AND "clientId" = $2 FOR SHARE', userId, before.clientId);
  await tx.$executeRawUnsafe('INSERT INTO tinycloud_native_consent_generation ("userId", "clientId", generation) VALUES ($1, $2, 0) ON CONFLICT DO NOTHING', userId, before.clientId);
  const generation = await tx.$queryRawUnsafe('SELECT generation FROM tinycloud_native_consent_generation WHERE "userId" = $1 AND "clientId" = $2 FOR SHARE', userId, before.clientId) as { generation: bigint }[];
  await tx.$queryRawUnsafe('SELECT id FROM tinycloud_native_request WHERE id = $1 FOR UPDATE', id);
  const row = await tx.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } });
  active(row);
  if (row.userId && row.userId !== userId) fail(403, 'request_user_mismatch');
  return { row, generation: generation[0]!.generation };
}
async function keyFor(tx: any, userId: string) {
  const key = await tx.ethereumKey.findFirst({ where: primaryKeyWhere(userId) });
  if (!key || !key.sealedBlob) fail(409, 'preparation_mismatch');
  return key as { id: string; address: string; sealedBlob: string; userId: string | null; sealingContext: string | null };
}
export interface NativeConsentHostOps {
  fetchPeerId: typeof fetchPeerId;
  activateSessionWithHost: typeof activateSessionWithHost;
  submitHostDelegation: typeof submitHostDelegation;
}
const defaultHostOps: NativeConsentHostOps = { fetchPeerId, activateSessionWithHost, submitHostDelegation };
export function createNativeDelegationConsentRouter(db: PrismaClient, hostOps: NativeConsentHostOps = defaultHostOps) {
  const router = new Hono<SessionContext>();
  router.use('*', async (c, next) => {
    const origin = c.req.header('origin');
    if (!origin || !resolveOriginPolicy('http://localhost:5173').includes(origin)) return c.json({ error: 'invalid_origin' }, 403);
    if (c.req.header('authorization')) return c.json({ error: 'unauthorized' }, 401);
    await next();
  });
  router.use('*', async (c, next) => {
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    if (!session) return c.json({ error: 'unauthorized' }, 401);
    c.set('user', session.user);
    c.set('session', session.session);
    await next();
  });
  router.onError((error, c) => {
    if (error instanceof NativeConsentError) return c.json({ error: error.code }, error.status, error.status === 503 ? { 'Retry-After': '2' } : undefined);
    const databaseError = error as { code?: string; meta?: { code?: string }; cause?: { code?: string } };
    const sqlstate = databaseError.code === 'P2010' ? databaseError.meta?.code : databaseError.code ?? databaseError.cause?.code;
    if (sqlstate === '40P01' || sqlstate === '55P03') return c.json({ error: 'temporarily_unavailable' }, 503, { 'Retry-After': '2' });
    throw error;
  });
  router.post('/:id/prepare', async (c) => {
    const body = await c.req.json().catch(() => ({})) as { actionKeys?: unknown };
    const userId = c.get('user').id;
    const result = await db.$transaction(async tx => {
      const { row } = await lockRequest(tx, c.req.param('id'), userId);
      const key = await keyFor(tx, userId);
      const client = await tx.oauthClient.findUniqueOrThrow({ where: { clientId: row.clientId }, include: { organization: { select: { name: true } } } });
      const ceiling = enabledNativeDelegation(client);
      if (!ceiling) fail(409, 'preparation_superseded');
      const requested = permitted(row.requestedPermissions, ceiling);
      const ttlSeconds = Math.min(row.ttlSeconds, ceiling.maxDelegationTtlSeconds, ceiling.grantLifetimeSeconds);
      const nonce = row.siweNonce ?? randomBytes(12).toString('base64url').replaceAll('-', 'A').replaceAll('_', 'B');
      const address = ensureEip55(key.address);
      const base = prepareSiwe(row, requested, key, ceiling, nonce, ttlSeconds, new Date());
      const permissions = selectedPermissions(requested, body.actionKeys, base.spaceId);
      const prepared = prepareSiwe(row, permissions, key, ceiling, nonce, ttlSeconds, new Date());
      const existing = await tx.tinyCloudBootstrapState.findFirst({ where: { keyId: key.id, chainId: 1, tinycloudHost: ceiling.tinycloudHost, status: 'complete' } });
      let hostPlan: { host: string; spaceId: string; peerId: string; hostSiwe: string } | null = null;
      if (!existing) {
        try {
          const peerId = await hostOps.fetchPeerId(ceiling.tinycloudHost, prepared.spaceId);
          hostPlan = { host: ceiling.tinycloudHost, spaceId: prepared.spaceId, peerId,
            hostSiwe: generateHostSIWEMessage({ address, chainId: 1, domain: ceiling.siweDomain ?? 'openkey.so', issuedAt: new Date().toISOString(), spaceId: prepared.spaceId, peerId }) };
        } catch { fail(503, 'temporarily_unavailable'); }
      }
      const revision = row.currentRevision + 1;
      const preview = { requestId: row.id, revision, userId, keyId: key.id, address, sessionSiwe: prepared.prepared.siwe, permissions, hostPlan };
      const digest = preparationDigest(preview);
      await tx.tinyCloudNativePreparation.create({ data: { id: randomUUID(), requestId: row.id, revision, userId, keyId: key.id, address, sessionSiwe: preview.sessionSiwe, permissions, hostPlan: hostPlan ?? undefined, digest } });
      await tx.tinyCloudNativeRequest.update({ where: { id: row.id }, data: { userId, siweNonce: nonce, currentRevision: revision } });
      return { ...preview, digest, client: { clientId: client.clientId, name: client.name, icon: client.icon, organization: client.organization?.name, verified: false }, redirectScheme: new URL(row.redirectUri).protocol.slice(0, -1), sessionDid: row.sessionDid, tinycloudHost: ceiling.tinycloudHost, ttlSeconds, grantLifetimeSeconds: ceiling.grantLifetimeSeconds, permissionOptions: prepared.permissions, selectedActionKeys: prepared.selectedActionKeys };
    });
    return c.json(result);
  });
  router.post('/:id/approve', async c => {
    const body = await c.req.json().catch(() => null) as { revision?: number; digest?: string; sessionSiwe?: string; hostSiwe?: string } | null;
    const userId = c.get('user').id;
    const result = await db.$transaction(async tx => {
      const { row, generation } = await lockRequest(tx, c.req.param('id'), userId);
      if (row.userId !== userId) fail(403, 'request_user_mismatch');
      if (!body || body.revision !== row.currentRevision) fail(409, 'preparation_superseded');
      const revision = await tx.tinyCloudNativePreparation.findUnique({ where: { requestId_revision: { requestId: row.id, revision: body.revision! } } });
      if (!revision || revision.digest !== body.digest || revision.sessionSiwe !== body.sessionSiwe) fail(409, 'preparation_mismatch');
      const hostPlan = revision.hostPlan as { host: string; spaceId: string; peerId: string; hostSiwe: string } | null;
      if ((hostPlan?.hostSiwe ?? undefined) !== body.hostSiwe) fail(409, 'preparation_mismatch');
      const key = await keyFor(tx, userId);
      if (key.id !== revision.keyId || ensureEip55(key.address) !== revision.address) fail(409, 'preparation_mismatch');
      const client = await tx.oauthClient.findUniqueOrThrow({ where: { clientId: row.clientId } });
      const ceiling = enabledNativeDelegation(client);
      if (!ceiling || revision.permissions == null) fail(409, 'preparation_superseded');
      const permissions = permitted(revision.permissions, ceiling);
      const ttl = Math.min(ceiling.maxDelegationTtlSeconds, ceiling.grantLifetimeSeconds);
      const timestamps = /Issued At: ([^\n]+)\nExpiration Time: ([^\n]+)/.exec(revision.sessionSiwe);
      const revisionTtl = timestamps ? (Date.parse(timestamps[2]!) - Date.parse(timestamps[1]!)) / 1000 : NaN;
      if (!Number.isInteger(revisionTtl) || revisionTtl > ttl) fail(409, 'preparation_superseded');
      if (!row.siweNonce) fail(409, 'preparation_mismatch');
      const signedAt = new Date();
      const rebuilt = prepareSiwe(row, permissions, key, ceiling, row.siweNonce, revisionTtl, signedAt);
      if (!sameApprovedSiwe(revision.sessionSiwe, rebuilt.prepared.siwe)) fail(409, 'preparation_mismatch');
      const signature = await signManagedKey(key, key.sealedBlob, rebuilt.prepared.siwe);
      const delegation = completeSessionSetup({ ...rebuilt.prepared, signature });
      const artifact = { version: 1, address: revision.address, chainId: 1, ownerDid: `did:pkh:eip155:1:${revision.address}`,
        sessionDid: row.sessionDid, sessionJkt: row.sessionJkt, issuedAt: signedAt.toISOString(),
        expiresAt: new Date(signedAt.getTime() + revisionTtl * 1000).toISOString(), siwe: rebuilt.prepared.siwe,
        signature, delegationHeader: delegation.delegationHeader, delegationCid: delegation.delegationCid,
        spaceId: delegation.spaceId, verificationMethod: delegation.verificationMethod, permissions,
        ttlSeconds: revisionTtl, tinycloudHost: ceiling.tinycloudHost };
      await tx.tinyCloudNativeRequest.update({ where: { id: row.id }, data: { status: 'APPROVED', approvedRevision: revision.revision, consentGeneration: generation, signature, delegation: artifact, hosting: 'failed' } });
      return { rowId: row.id, revision: revision.revision, hostPlan, artifact, key };
    });
    let hosting: 'existing' | 'created' | 'failed' = 'failed';
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
            if (retry.success && retry.activated?.includes(result.artifact.spaceId)) hosting = 'created';
          }
        }
      }
    } catch { /* Activation failure is reported in the code artifact. */ }
    await db.tinyCloudNativeRequest.update({ where: { id: result.rowId }, data: { hosting } });
    return c.json({ status: 'APPROVED', revision: result.revision, hosting });
  });
  router.post('/:id/deny', async c => {
    const userId = c.get('user').id;
    await db.$transaction(async tx => {
      const { row } = await lockRequest(tx, c.req.param('id'), userId);
      await tx.tinyCloudNativeRequest.update({ where: { id: row.id }, data: { status: 'DENIED' } });
    });
    return c.json({ status: 'DENIED' });
  });
  return router;
}
