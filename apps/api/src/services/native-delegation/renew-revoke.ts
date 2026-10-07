import { randomBytes, randomUUID } from 'node:crypto';
import { generateRandomString } from 'better-auth/crypto';
import type { PrismaClient } from '@openkey/db';
import { ensureEip55, completeSessionSetup } from '@tinycloud/node-sdk-wasm';
import { createWalletFromPrivateKey } from '@openkey/tee';
import { primaryKeyWhere } from '../primary-key';
import { unsealManagedKey } from '../managed-key-signing';
import { prepareDelegationSession } from '../../routes/delegate-session';
import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { nativeDelegationLockResponse } from './errors';
import { validatePermissions, ParError, type NativePermission } from './par';
import { enabledNativeDelegation } from './policy';
import { storedToken } from './provider-tokens';
import { NATIVE_DELEGATION_ENDPOINT_PATHS, OPENKEY_SESSION_PROOF_HEADER } from './public-protocol';
import { credentialHash, verifySessionProof } from './session-proof';

const REFRESH_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
const RENEWAL_CUTOFF_MS = 300_000;
const CONFLICT_WINDOW_MS = 30_000;
const FORM_KEYS = new Set(['client_id', 'refresh_token', 'siwe_nonce', 'authorization_details']);
const DETAIL_KEYS = new Set(['type', 'session_key', 'permissions']);

type Operation = 'renew' | 'revoke';
type Failure = { error: string; status: 400 | 401 | 409 | 429; retryAfter?: number };
type Result = { failure: Failure } | { body: Record<string, unknown> };

class KeyUnsealTimeout extends Error {}

function fail(error: Failure['error'], status: Failure['status'], retryAfter?: number): Result {
  return { failure: { error, status, ...(retryAfter ? { retryAfter } : {}) } };
}

function respond(result: Result): Response {
  const headers = { 'Cache-Control': 'no-store', 'Pragma': 'no-cache' };
  if ('failure' in result) return Response.json({ error: result.failure.error }, {
    status: result.failure.status,
    headers: { ...headers, ...(result.failure.retryAfter ? { 'Retry-After': String(result.failure.retryAfter) } : {}) },
  });
  return Response.json(result.body, { headers });
}

function permissionSubset(requested: NativePermission[], approved: NativePermission[]): boolean {
  return requested.every((entry) => {
    const parent = approved.find((candidate) => candidate.service === entry.service && candidate.space === entry.space &&
      (candidate.path === entry.path || (candidate.service === 'tinycloud.kv' && candidate.path.endsWith('/') && entry.path.startsWith(candidate.path))));
    return !!parent && entry.actions.every((action) => parent.actions.includes(action));
  });
}

function requestedPermissions(raw: string | null, jwk: unknown): unknown {
  if (raw === null) return undefined;
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { return null; }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !parsed[0] || typeof parsed[0] !== 'object' || Array.isArray(parsed[0])) return null;
  const detail = parsed[0] as Record<string, unknown>;
  const suppliedKey = detail.session_key;
  const storedKey = jwk as Record<string, unknown>;
  const sameKey = !!suppliedKey && typeof suppliedKey === 'object' && !Array.isArray(suppliedKey) &&
    Object.keys(suppliedKey).length === Object.keys(storedKey).length &&
    Object.entries(suppliedKey).every(([key, value]) => Object.hasOwn(storedKey, key) && storedKey[key] === value);
  if (Object.keys(detail).length !== 3 || Object.keys(detail).some((key) => !DETAIL_KEYS.has(key)) || detail.type !== 'tinycloud_delegation' ||
    !sameKey) return null;
  return detail.permissions;
}

async function deleteGrantTokens(tx: any, grant: { refreshTokenHash: string | null; previousRefreshTokenHash: string | null; userId: string; clientId: string }) {
  const hashes = [grant.refreshTokenHash, grant.previousRefreshTokenHash].filter((value): value is string => !!value);
  if (!hashes.length) return;
  const rows = await tx.oauthRefreshToken.findMany({ where: { token: { in: hashes }, userId: grant.userId, clientId: grant.clientId }, select: { id: true } });
  if (rows.length) await tx.oauthAccessToken.deleteMany({ where: { refreshId: { in: rows.map((row: { id: string }) => row.id) } } });
  await tx.oauthRefreshToken.deleteMany({ where: { id: { in: rows.map((row: { id: string }) => row.id) } } });
}

async function recordDecision(tx: any, grant: { userId: string; clientId: string }, epoch: bigint, allowed: boolean, reason: string) {
  await tx.tinyCloudManageKeySigningDecision.create({ data: {
    id: randomUUID(), userId: grant.userId, clientId: grant.clientId, policyEpoch: epoch, allowed, reason,
  } });
}

/** Public, cookie-free native endpoint. Every mutation is serialized with consent withdrawal. */
export async function handleNativeRenewOrRevoke(request: Request, db: PrismaClient, issuer: string, operation: Operation): Promise<Response> {
  const invalidProof = () => respond(fail('invalid_session_proof', 401));
  try {
    if ((request.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase() !== 'application/x-www-form-urlencoded') return respond(fail('invalid_request', 400));
    const params = new URLSearchParams(await request.text());
    const keys = [...params.keys()];
    if (new Set(keys).size !== keys.length || keys.some((key) => !FORM_KEYS.has(key)) ||
      (operation === 'revoke' && keys.some((key) => key !== 'client_id' && key !== 'refresh_token')) ||
      !params.get('client_id') || !params.get('refresh_token')) return respond(fail('invalid_request', 400));
    const token = params.get('refresh_token')!;
    const hash = credentialHash(token);
    const candidate = await db.tinyCloudNativeGrant.findFirst({ where: { OR: [{ refreshTokenHash: hash }, { previousRefreshTokenHash: hash }] } });
    if (!candidate || candidate.clientId !== params.get('client_id')) return invalidProof();
    if (!verifySessionProof(request.headers.get(OPENKEY_SESSION_PROOF_HEADER), {
      sessionJwk: candidate.sessionJwk as { x: string }, sessionJkt: candidate.sessionJkt,
      htu: `${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS[operation]}`, clientId: candidate.clientId, credential: token,
    })) return invalidProof();

    const nonce = params.get('siwe_nonce');
    if (operation === 'renew' && nonce !== null && !/^[A-Za-z0-9]{8,64}$/.test(nonce)) return respond(fail('invalid_authorization_details', 400));
    const requested = operation === 'renew' ? requestedPermissions(params.get('authorization_details'), candidate.sessionJwk) : undefined;
    if (operation === 'renew' && requested === null) return respond(fail('invalid_authorization_details', 400));

    // Unsealing can contact the TEE. Do it before taking database locks, then
    // compare the canonical key and sealed blob again under the transaction.
    const preKey = operation === 'renew' && candidate.status === 'ACTIVE' && candidate.refreshTokenHash === hash
      ? await db.ethereumKey.findFirst({ where: primaryKeyWhere(candidate.userId) }) : null;
    let privateKey: Awaited<ReturnType<typeof unsealManagedKey>> | null = null;
    if (preKey?.sealedBlob && preKey.id === candidate.keyId) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        privateKey = await Promise.race([
          unsealManagedKey(preKey, preKey.sealedBlob),
          new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new KeyUnsealTimeout()), 5_000); }),
        ]);
      } catch (error) {
        // Keep TEE and sealed-key details out of the response. Only a timed
        // out operation is classified as retryable.
        return error instanceof KeyUnsealTimeout
          ? Response.json({ error: 'temporarily_unavailable' }, { status: 503, headers: { 'Retry-After': '2', 'Cache-Control': 'no-store' } })
          : Response.json({ error: 'key_unavailable' }, { status: 500, headers: { 'Cache-Control': 'no-store' } });
      } finally { if (timer) clearTimeout(timer); }
    }

    const result: Result = await db.$transaction(async (tx) => {
      await tx.$executeRaw`SET LOCAL lock_timeout = '5s'`;
      const consents = await tx.$queryRaw<{ id: string; scopes: string[] }[]>`
        SELECT id, scopes FROM oauth_consent WHERE "userId" = ${candidate.userId} AND "clientId" = ${candidate.clientId} FOR SHARE`;
      const generations = await tx.$queryRaw<{ generation: bigint }[]>`
        SELECT generation FROM tinycloud_native_consent_generation WHERE "userId" = ${candidate.userId} AND "clientId" = ${candidate.clientId} FOR SHARE`;
      await tx.$queryRaw`SELECT id FROM tinycloud_native_grant WHERE id = ${candidate.id} FOR UPDATE`;
      const grant = await tx.tinyCloudNativeGrant.findUnique({ where: { id: candidate.id } });
      if (!grant || (grant.refreshTokenHash !== hash && grant.previousRefreshTokenHash !== hash)) return fail('invalid_grant', 400);
      if (operation === 'revoke') {
        if (grant.status !== 'REVOKED') await tx.tinyCloudNativeGrant.update({ where: { id: grant.id }, data: { status: 'REVOKED', revokedAt: new Date(), revokedReason: 'client_signout' } });
        await deleteGrantTokens(tx, grant);
        return { body: {} };
      }
      if (grant.status !== 'ACTIVE') return fail('invalid_grant', 400);
      if (!consents.some((consent) => consent.id === grant.consentId && consent.scopes.includes(TINYCLOUD_DELEGATION_SCOPE)) ||
        generations[0]?.generation !== grant.consentGeneration) return fail('consent_required', 400);
      const now = new Date();
      if (grant.previousRefreshTokenHash === hash) {
        if (grant.rotatedAt && now.getTime() - grant.rotatedAt.getTime() <= CONFLICT_WINDOW_MS) return fail('renewal_conflict', 409);
        await tx.tinyCloudNativeGrant.update({ where: { id: grant.id }, data: { status: 'REVOKED', revokedAt: now, revokedReason: 'refresh_reuse' } });
        await deleteGrantTokens(tx, grant);
        return fail('invalid_grant', 400);
      }
      const tokenRows = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM oauth_refresh_token WHERE token = ${hash} FOR UPDATE`;
      if (!tokenRows.length) return fail('invalid_grant', 400);
      const row = await tx.oauthRefreshToken.findUnique({ where: { token: hash } });
      if (!row || row.userId !== grant.userId || row.clientId !== grant.clientId || !row.scopes.includes(TINYCLOUD_DELEGATION_SCOPE) ||
        row.revoked || row.expiresAt <= now) return fail('invalid_grant', 400);
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${grant.userId} FOR SHARE`;
      const user = await tx.user.findUnique({ where: { id: grant.userId }, select: { tinyCloudManageKeyMode: true, tinyCloudManageKeyPolicyEpoch: true } });
      if (!user) return fail('invalid_grant', 400);
      const epoch = user?.tinyCloudManageKeyPolicyEpoch ?? 0n;
      const deny = async (code: 'consent_required' | 'access_denied', reason: string) => {
        await recordDecision(tx, grant, epoch, false, reason);
        return fail(code, 400);
      };
      if (now.getTime() >= grant.absoluteExpiresAt.getTime() - RENEWAL_CUTOFF_MS) return deny('consent_required', 'grant_expired');
      const client = await tx.oauthClient.findUnique({ where: { clientId: grant.clientId } });
      const ceiling = client && enabledNativeDelegation(client);
      if (!ceiling || ceiling.tinycloudHost !== grant.tinycloudHost) return deny('consent_required', 'ceiling_changed');
      const approved = grant.approvedPermissions as NativePermission[];
      let permissions: NativePermission[];
      try {
        validatePermissions(approved, ceiling);
      } catch (error) {
        if (error instanceof ParError) return deny('consent_required', 'ceiling_changed');
        throw error;
      }
      if (requested !== undefined) {
        try { permissions = validatePermissions(requested, ceiling); }
        catch (error) {
          if (error instanceof ParError) return fail('invalid_authorization_details', 400);
          throw error;
        }
      } else permissions = approved;
      if (requested !== undefined && !permissionSubset(permissions, approved)) return fail('invalid_authorization_details', 400);
      const key = await tx.ethereumKey.findFirst({ where: primaryKeyWhere(grant.userId) });
      if (!key || key.id !== grant.keyId || key.address.toLowerCase() !== grant.address.toLowerCase() ||
        !privateKey || key.sealedBlob !== preKey?.sealedBlob) return deny('consent_required', 'key_changed');
      if (user?.tinyCloudManageKeyMode === 'USER_CONTROLLED_EXCLUSIVE') return deny('access_denied', 'user_exclusive');
      const preference = await tx.tinyCloudManageKeyAppPreference.findUnique({ where: { userId_clientId: { userId: grant.userId, clientId: grant.clientId } } });
      if (preference?.status === 'DISABLED' || preference?.enabled === false) return deny('access_denied', 'grant_disabled');
      const interval = Math.min(60, grant.ttlSeconds / 4) * 1000;
      if (grant.lastRenewedAt && now.getTime() < grant.lastRenewedAt.getTime() + interval) {
        return fail('renewal_too_soon', 429, Math.max(1, Math.ceil((grant.lastRenewedAt.getTime() + interval - now.getTime()) / 1000)));
      }
      const ttlSeconds = Math.min(grant.ttlSeconds, ceiling.maxDelegationTtlSeconds,
        Math.floor((grant.absoluteExpiresAt.getTime() - now.getTime()) / 1000));
      if (ttlSeconds <= 0) return deny('consent_required', 'grant_expired');
      const siweNonce = nonce ?? randomBytes(12).toString('hex');
      const prepared = prepareDelegationSession({ address: ensureEip55(key.address), chainId: 1, prefix: 'applications',
        jwk: grant.sessionJwk as { kty: string; crv: string; x: string }, permissions, expiryMs: ttlSeconds * 1000,
        domain: ceiling.siweDomain ?? 'openkey.so', nonce: siweNonce, issuedAt: now });
      if (prepared.spaceId !== grant.spaceId || prepared.prepared.verificationMethod !== grant.sessionDid) return deny('consent_required', 'session_changed');
      const signature = await createWalletFromPrivateKey(privateKey).signMessage({ message: prepared.prepared.siwe });
      const delegation = completeSessionSetup({ ...prepared.prepared, signature });
      const newToken = generateRandomString(32, 'A-Z', 'a-z');
      const newHash = await storedToken({ storeTokens: 'hashed' }, newToken, 'refresh_token');
      const expiresAt = new Date(now.getTime() + REFRESH_LIFETIME_SECONDS * 1000);
      await tx.oauthRefreshToken.update({ where: { id: row.id }, data: { revoked: now } });
      await tx.oauthRefreshToken.create({ data: {
        id: randomUUID(), token: newHash, clientId: row.clientId, userId: row.userId, sessionId: row.sessionId,
        referenceId: row.referenceId, scopes: row.scopes, authTime: row.authTime, expiresAt,
      } });
      await tx.tinyCloudNativeGrant.update({ where: { id: grant.id }, data: {
        previousRefreshTokenHash: hash, refreshTokenHash: newHash, rotatedAt: now, lastRenewedAt: now, renewCount: { increment: 1 },
      } });
      await recordDecision(tx, grant, epoch, true, 'native_renew');
      return { body: {
        refresh_token: newToken, expires_in: REFRESH_LIFETIME_SECONDS,
        tinycloud_delegation: {
          version: 1, grantId: grant.id, verificationMethod: delegation.verificationMethod,
          siwe: prepared.prepared.siwe, signature, delegationHeader: delegation.delegationHeader,
          delegationCid: delegation.delegationCid, issuedAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
          renewableUntil: new Date(grant.absoluteExpiresAt.getTime() - RENEWAL_CUTOFF_MS).toISOString(),
          permissions, tinycloudHost: grant.tinycloudHost, hosting: 'existing', address: grant.address,
          chainId: 1, ownerDid: `did:pkh:eip155:1:${grant.address}`, spaceId: grant.spaceId,
        },
      } };
    }, { timeout: 15_000 });
    return respond(result);
  } catch (error) {
    const locked = nativeDelegationLockResponse(error);
    if (locked) return locked;
    throw error;
  }
}
