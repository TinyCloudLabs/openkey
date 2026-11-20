import { lockNativeReviewer, nativeReviewerAuthority } from '../reviewer-native';
import { randomBytes } from 'node:crypto';
import { APIError } from 'better-auth/api';
import { generateRandomString } from 'better-auth/crypto';
import { defineRequestState, getCurrentAuthContext } from '@better-auth/core/context';
import type { PrismaClient, Prisma } from '@openkey/db';
import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { isNativeDelegationLockTimeout, nativeDelegationSqlState } from './errors';
import { enabledNativeDelegation } from './policy';
import { storedToken, type ProviderTokenOptions } from './provider-tokens';
import { OPENKEY_SESSION_PROOF_HEADER } from './public-protocol';
import { verifySessionProof } from './session-proof';
import type { NativePermission } from './par';
import { StepUpEntryError, validateStepUpPermissions, type StepUpPermission } from './step-up';
import { primaryKeyWhere } from '../primary-key';
import { sameTinyCloudHost } from '../tinycloud-hosts';

/**
 * Native code exchange (spec: "Code exchange and token response"), run from
 * the provider's `customTokenResponseFields` for `authorization_code`.
 *
 * better-auth has already deleted the code, checked PKCE, the client and the
 * redirect URI against the code's stored query. That query is not trusted
 * here: social sign-in's after-hook can reach the provider's authorize
 * endpoint without the Hono `tinycloud_request` guard, so every binding is
 * matched against the request row, inside the atomic redemption.
 *
 * The hook runs before the provider writes any token row. It commits the
 * redemption and the grant; the provider then creates the refresh token
 * outside this transaction, and `generateNativeRefreshToken` links its hash
 * to the grant. A failure after the commit leaves the grant unlinked, which
 * renewal refuses. A consent withdrawal that lands after linking but before
 * the provider's token inserts is caught by the token guard triggers
 * (20261007_0003): the insert fails and no live token exists for the
 * revoked grant.
 */

const RENEWAL_CUTOFF_MS = 300_000;
/** SQLSTATE raised by the token guard triggers (20261007_0003). */
const NATIVE_GRANT_NOT_LIVE = 'TC773';
const TOKEN_PATH = '/oauth2/token';

/** The grant this request's code exchange committed, awaiting its refresh token. */
const pendingNativeGrant = defineRequestState<string | undefined>(() => undefined);

/** The artifact approve stores on the request (`request.delegation`). */
interface ApprovedDelegation {
  version: 1;
  address: string;
  chainId: number;
  ownerDid: string;
  issuedAt: string;
  expiresAt: string;
  siwe: string;
  signature: string;
  delegationHeader: { Authorization: string };
  delegationCid: string;
  spaceId: string;
  verificationMethod: string;
  permissions: NativePermission[];
  ttlSeconds: number;
  tinycloudHost: string;
}

/** The artifact a step-up approve stores: the sign-in artifact plus the grant and app it is bound to. */
interface ApprovedStepUpDelegation extends ApprovedDelegation {
  sessionDid: string;
  grantId: string;
  appId: string;
}

type NativeRequest = Prisma.TinyCloudNativeRequestGetPayload<Record<string, never>>;

function isApprovedStepUpDelegation(value: unknown): value is ApprovedStepUpDelegation {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const entry = value as Record<string, unknown>;
  const header = entry.delegationHeader;
  return ['address', 'ownerDid', 'issuedAt', 'expiresAt', 'siwe', 'signature', 'delegationCid', 'verificationMethod', 'tinycloudHost', 'sessionDid', 'grantId', 'appId']
    .every((field) => typeof entry[field] === 'string' && (entry[field] as string).length > 0) &&
    typeof entry.chainId === 'number' && Array.isArray(entry.permissions) &&
    !!header && typeof header === 'object' && typeof (header as Record<string, unknown>).Authorization === 'string';
}

export interface NativeCodeExchangeInput {
  user?: { id: string } | null;
  scopes: string[];
  verificationValue?: { query?: object } | null;
}

function invalidGrant(description: string): never {
  throw new APIError('BAD_REQUEST', { error: 'invalid_grant', error_description: description });
}

/**
 * Every failure after the provider deleted the code is final for that code.
 * Lock contention maps to 503 with `Retry-After`; the description says the
 * code cannot be retried, because the SDK must start a new authorization.
 */
function spentCodeError(error: unknown): unknown {
  if (isNativeDelegationLockTimeout(error)) {
    return new APIError('SERVICE_UNAVAILABLE', {
      error: 'temporarily_unavailable',
      error_description: 'lock contention; the authorization code is already spent and cannot be retried, start a new authorization',
    }, { 'Retry-After': '2' });
  }
  if (nativeDelegationSqlState(error) === NATIVE_GRANT_NOT_LIVE) {
    return new APIError('BAD_REQUEST', {
      error: 'invalid_grant',
      error_description: 'consent was withdrawn while the tokens were issued; the authorization code is already spent, start a new authorization',
    });
  }
  return error;
}

function bound(query: Record<string, unknown>, key: string): string {
  const value = query[key];
  // Prisma drops an `undefined` filter, so a missing value must never reach
  // the redemption's WHERE clause.
  if (typeof value !== 'string' || !value) invalidGrant(`authorization code is missing ${key}`);
  return value;
}

/**
 * Returns the extra token-response fields for a native delegation code, or
 * `{}` for an ordinary code. Throws the spec's OAuth errors otherwise.
 */
export async function exchangeNativeCode(
  db: PrismaClient,
  issuer: string,
  { user, scopes, verificationValue }: NativeCodeExchangeInput,
): Promise<Record<string, unknown>> {
  const query = (verificationValue?.query ?? {}) as Record<string, unknown>;
  if (!scopes.includes(TINYCLOUD_DELEGATION_SCOPE) && !('tinycloud_request' in query)) return {};

  const ctx = await getCurrentAuthContext();
  // The provider issues a JWT access token, with no token row for consent
  // withdrawal to revoke, when the request names a `resource`. The token
  // interceptor refuses it first; this covers any path around the interceptor.
  if ((ctx.body as { resource?: unknown } | undefined)?.resource !== undefined) {
    throw new APIError('BAD_REQUEST', {
      error: 'invalid_request',
      error_description: 'resource is not supported for native delegation clients',
    });
  }
  const requestId = query.tinycloud_request;
  if (typeof requestId !== 'string' || !requestId) invalidGrant('authorization code has no native delegation request');
  const request = await db.tinyCloudNativeRequest.findUnique({ where: { id: requestId } });
  if (!request) invalidGrant('no approved native delegation request for this code');
  // A step-up code is redeemed by its own branch; the sign-in branch below only ever mints a grant.
  if (request.kind !== 'SIGNIN' && request.kind !== 'STEPUP') invalidGrant('authorization code does not match its native delegation request');
  const binding = {
    clientId: bound(query, 'client_id'),
    redirectUri: bound(query, 'redirect_uri'),
    state: bound(query, 'state'),
    codeChallenge: bound(query, 'code_challenge'),
  };
  if (query.scope !== request.scopes.join(' ') || query.code_challenge_method !== 'S256') {
    invalidGrant('authorization code does not match its native delegation request');
  }
  if (!user?.id) invalidGrant('authorization code has no user');
  const userId = user.id;
  if (request.kind === 'STEPUP') return await exchangeStepUp(db, issuer, request, userId, binding);

  const code = (ctx.body as { code?: unknown } | undefined)?.code;
  const proof = ctx.request?.headers.get(OPENKEY_SESSION_PROOF_HEADER);
  if (typeof code !== 'string' || !verifySessionProof(proof, {
    sessionJwk: request.sessionJwk as { x: string },
    sessionJkt: request.sessionJkt,
    htu: `${issuer}${TOKEN_PATH}`,
    clientId: request.clientId,
    credential: code,
  })) {
    throw new APIError('UNAUTHORIZED', { error: 'invalid_session_proof', error_description: 'missing or invalid OpenKey-Session-Proof' });
  }

  let redeemed: { grantId: string; fields: Record<string, unknown> };
  try {
    // Lock order: consent -> generation -> request -> grant. The 15 s
    // transaction timeout leaves the 5 s lock timeout to fire first.
    redeemed = await db.$transaction(async (tx) => {
      await tx.$executeRaw`SET LOCAL lock_timeout = '5s'`;
      const reviewerBinding = await lockNativeReviewer(tx, userId);
      const consents = await tx.$queryRaw<{ id: string; scopes: string[] | null }[]>`
        SELECT id, scopes FROM oauth_consent
        WHERE "userId" = ${userId} AND "clientId" = ${request.clientId} FOR SHARE`;
      const consent = consents.find((row) => row.scopes?.includes(TINYCLOUD_DELEGATION_SCOPE));
      if (!consent) invalidGrant('consent is missing or withdrawn');
      const generations = await tx.$queryRaw<{ generation: bigint }[]>`
        SELECT generation FROM tinycloud_native_consent_generation
        WHERE "userId" = ${userId} AND "clientId" = ${request.clientId} FOR SHARE`;
      const generation = generations[0]?.generation;
      if (generation === undefined) invalidGrant('consent changed since approval');

      // Exactly one of two concurrent redemptions matches. The generation
      // ties the code to the consent current at approve, so a code approved
      // before a delete and re-consent cannot adopt the new consent.
      const swapped = await tx.tinyCloudNativeRequest.updateMany({
        where: { id: request.id, status: 'APPROVED', userId, consentGeneration: generation, ...binding },
        data: { status: 'REDEEMED' },
      });
      if (swapped.count !== 1) invalidGrant('no approved native delegation request for this code');

      const row = await tx.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: request.id } });
      if (row.approvedRevision === null || row.delegation === null || row.hosting === null) {
        throw new Error(`approved native request ${row.id} lacks its approval`);
      }
      const delegation = row.delegation as unknown as ApprovedDelegation;
      const preparation = await tx.tinyCloudNativePreparation.findUniqueOrThrow({
        where: { requestId_revision: { requestId: row.id, revision: row.approvedRevision } },
      });
      const client = await tx.oauthClient.findUniqueOrThrow({ where: { clientId: row.clientId } });
      const ceiling = enabledNativeDelegation(client);
      if (!ceiling) invalidGrant('native delegation is no longer enabled for this client');

      const reviewer = await nativeReviewerAuthority(tx, userId, row, reviewerBinding);
      const now = Date.now();
      const absoluteExpiresAt = new Date(reviewer?.deadline ?? now + ceiling.grantLifetimeSeconds * 1000);
      if (reviewer && (preparation.keyId !== reviewer.binding.keyId || delegation.spaceId !== reviewer.binding.spaceId
        || delegation.tinycloudHost !== reviewer.binding.nodeHost)) invalidGrant('review account binding changed');
      if (Date.parse(delegation.expiresAt) > absoluteExpiresAt.getTime()) {
        invalidGrant('the approved delegation would outlive the grant');
      }
      const grantId = randomBytes(24).toString('base64url');
      await tx.tinyCloudNativeGrant.create({ data: {
        id: grantId,
        userId,
        clientId: row.clientId,
        consentId: consent.id,
        consentGeneration: generation,
        keyId: preparation.keyId,
        address: delegation.address,
        sessionDid: row.sessionDid,
        sessionJwk: row.sessionJwk as object,
        sessionJkt: row.sessionJkt,
        spaceId: delegation.spaceId,
        approvedPermissions: delegation.permissions,
        ttlSeconds: delegation.ttlSeconds,
        tinycloudHost: delegation.tinycloudHost,
        absoluteExpiresAt,
        ...(reviewer ? { reviewerEpoch: reviewer.binding.installEpoch } : {}),
      } });

      return {
        grantId,
        fields: {
          authorization_details: [{
            type: 'tinycloud_delegation',
            session_key: row.sessionJwk,
            permissions: delegation.permissions,
            ttl_seconds: delegation.ttlSeconds,
          }],
          tinycloud_delegation: {
            version: 1,
            grantId,
            address: delegation.address,
            chainId: delegation.chainId,
            ownerDid: delegation.ownerDid,
            spaceId: delegation.spaceId,
            verificationMethod: delegation.verificationMethod,
            siwe: delegation.siwe,
            signature: delegation.signature,
            delegationHeader: delegation.delegationHeader,
            delegationCid: delegation.delegationCid,
            issuedAt: delegation.issuedAt,
            expiresAt: delegation.expiresAt,
            renewableUntil: new Date(absoluteExpiresAt.getTime() - (reviewer ? 0 : RENEWAL_CUTOFF_MS)).toISOString(),
            // A separate copy: better-call's serializer writes a second
            // reference to the same object as "[Circular ref-N]".
            permissions: structuredClone(delegation.permissions),
            tinycloudHost: delegation.tinycloudHost,
            hosting: row.hosting,
          },
        },
      };
    }, { timeout: 15_000 });
  } catch (error) {
    throw spentCodeError(error);
  }
  await pendingNativeGrant.set(redeemed.grantId);
  // The provider passes these to `ctx.json`, which better-auth's router drops
  // (it runs endpoints with `asResponse: false`); response headers set on the
  // endpoint context are kept.
  ctx.setHeader!('Cache-Control', 'no-store');
  ctx.setHeader!('Pragma', 'no-cache');
  return redeemed.fields;
}

/**
 * TC-3569: the code exchange of an approved `STEPUP` request. It adds nothing to the user's consent and mints
 * neither a grant nor a refresh token: the only writes are the request's redemption and the grant's step-up row.
 * The code is bound to its request, the grant and PKCE, and the proof is verified against the GRANT's key. The
 * hook runs before the provider writes any token, and the request's scopes carry no `offline_access`, so the
 * provider writes one short-lived access token that holds only `tinycloud:delegation`.
 */
async function exchangeStepUp(
  db: PrismaClient,
  issuer: string,
  request: NativeRequest,
  userId: string,
  binding: { clientId: string; redirectUri: string; state: string; codeChallenge: string },
): Promise<Record<string, unknown>> {
  const ctx = await getCurrentAuthContext();
  const code = (ctx.body as { code?: unknown } | undefined)?.code;
  const proof = ctx.request?.headers.get(OPENKEY_SESSION_PROOF_HEADER);
  const home = request.grantId ? await db.tinyCloudNativeGrant.findUnique({ where: { id: request.grantId } }) : null;
  if (!home || !request.appId || home.sessionJkt !== request.sessionJkt) invalidGrant('authorization code does not match its native delegation request');
  if (typeof code !== 'string' || !verifySessionProof(proof, {
    sessionJwk: home.sessionJwk as { x: string },
    sessionJkt: home.sessionJkt,
    htu: `${issuer}${TOKEN_PATH}`,
    clientId: request.clientId,
    credential: code,
  })) {
    throw new APIError('UNAUTHORIZED', { error: 'invalid_session_proof', error_description: 'missing or invalid OpenKey-Session-Proof' });
  }
  const appId = request.appId;
  let fields: Record<string, unknown>;
  try {
    // Lock order: reviewer, consent, generation, request, grant, step-up, token row.
    fields = await db.$transaction(async (tx) => {
      await tx.$executeRaw`SET LOCAL lock_timeout = '5s'`;
      if (await lockNativeReviewer(tx, userId)) invalidGrant('review accounts cannot step up');
      // A concurrent switch to user-controlled keys takes this row FOR UPDATE; it cannot land between here and the commit.
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR SHARE`;
      const consents = await tx.$queryRaw<{ id: string; scopes: string[] | null }[]>`
        SELECT id, scopes FROM oauth_consent
        WHERE "userId" = ${userId} AND "clientId" = ${request.clientId} FOR SHARE`;
      if (!consents.some((row) => row.scopes?.includes(TINYCLOUD_DELEGATION_SCOPE))) invalidGrant('consent is missing or withdrawn');
      const generations = await tx.$queryRaw<{ generation: bigint }[]>`
        SELECT generation FROM tinycloud_native_consent_generation
        WHERE "userId" = ${userId} AND "clientId" = ${request.clientId} FOR SHARE`;
      const generation = generations[0]?.generation;
      if (generation === undefined) invalidGrant('consent changed since approval');

      // Exactly one of two concurrent redemptions matches; only an approval that finished hosting can be redeemed.
      const swapped = await tx.tinyCloudNativeRequest.updateMany({
        where: { id: request.id, kind: 'STEPUP', status: 'APPROVED', userId, consentGeneration: generation, hosting: 'existing', grantId: home.id, appId, ...binding },
        data: { status: 'REDEEMED' },
      });
      if (swapped.count !== 1) invalidGrant('no approved native delegation request for this code');
      const row = await tx.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: request.id } });
      if (row.approvedRevision === null || row.delegation === null) throw new Error(`approved native request ${row.id} lacks its approval`);
      // A DENIED approval reuses this column for its revoke record, which carries no signature: never redeemable.
      if (!isApprovedStepUpDelegation(row.delegation)) throw new Error(`approved step-up request ${row.id} holds a malformed delegation`);
      const delegation = row.delegation;
      const preparation = await tx.tinyCloudNativePreparation.findUniqueOrThrow({
        where: { requestId_revision: { requestId: row.id, revision: row.approvedRevision } },
      });

      // The grant must still be the live one this step-up was made for.
      await tx.$queryRaw`SELECT id FROM tinycloud_native_grant WHERE id = ${home.id} FOR SHARE`;
      const grant = await tx.tinyCloudNativeGrant.findUnique({ where: { id: home.id } });
      const now = Date.now();
      if (!grant || grant.status !== 'ACTIVE' || grant.userId !== userId || grant.clientId !== row.clientId || grant.consentGeneration !== generation ||
        grant.sessionJkt !== row.sessionJkt || grant.sessionDid !== row.sessionDid || now >= grant.absoluteExpiresAt.getTime() - RENEWAL_CUTOFF_MS) {
        invalidGrant('the grant is no longer active');
      }
      await tx.$queryRaw`SELECT id FROM oauth_refresh_token WHERE token = ${grant.refreshTokenHash} FOR SHARE`;
      const token = grant.refreshTokenHash ? await tx.oauthRefreshToken.findUnique({ where: { token: grant.refreshTokenHash } }) : null;
      if (!token || token.userId !== userId || token.clientId !== grant.clientId || token.revoked || token.expiresAt.getTime() <= now) invalidGrant('the grant is no longer active');
      const account = await tx.user.findUnique({ where: { id: userId }, select: { lockedAt: true, reviewerHoldAt: true, tinyCloudManageKeyMode: true } });
      if (!account || account.lockedAt || account.reviewerHoldAt || account.tinyCloudManageKeyMode === 'USER_CONTROLLED_EXCLUSIVE') invalidGrant('the account cannot step up');
      const preference = await tx.tinyCloudManageKeyAppPreference.findUnique({ where: { userId_clientId: { userId, clientId: grant.clientId } } });
      if (preference?.status === 'DISABLED' || preference?.enabled === false) invalidGrant('the app is switched off');
      const key = await tx.ethereumKey.findFirst({ where: primaryKeyWhere(userId) });
      if (!key || !key.sealedBlob || key.id !== grant.keyId || key.id !== preparation.keyId ||
        key.address.toLowerCase() !== grant.address.toLowerCase() || key.address.toLowerCase() !== delegation.address.toLowerCase()) invalidGrant('the grant key changed');
      const client = await tx.oauthClient.findUniqueOrThrow({ where: { clientId: row.clientId } });
      const ceiling = enabledNativeDelegation(client);
      if (!ceiling || !sameTinyCloudHost(ceiling.tinycloudHost, grant.tinycloudHost) || !sameTinyCloudHost(ceiling.tinycloudHost, delegation.tinycloudHost)) {
        invalidGrant('native delegation is no longer enabled for this client');
      }
      let permissions: StepUpPermission[];
      try { permissions = validateStepUpPermissions(appId, delegation.permissions, ceiling.stepUps); }
      catch (error) { if (error instanceof StepUpEntryError) invalidGrant('the approved permissions are beyond the step-up ceiling'); throw error; }
      // The delegation is for this grant's own session key and ends with, at the latest, the grant.
      const expiresAt = Date.parse(delegation.expiresAt);
      if (delegation.grantId !== grant.id || delegation.appId !== appId || delegation.sessionDid !== grant.sessionDid ||
        !(expiresAt > now) || expiresAt > grant.absoluteExpiresAt.getTime()) invalidGrant('the approved delegation does not match the grant');

      const existing = await tx.tinyCloudNativeStepUp.findUnique({ where: { grantId_appId: { grantId: grant.id, appId } } });
      const approvedAt = new Date(now);
      if (!existing) {
        await tx.tinyCloudNativeStepUp.create({ data: { id: randomBytes(24).toString('base64url'), grantId: grant.id, appId, approvedPermissions: permissions, approvedAt } });
      } else if (existing.status === 'ACTIVE') {
        await tx.tinyCloudNativeStepUp.update({ where: { id: existing.id }, data: { approvedPermissions: permissions, approvedAt } });
      } else if (existing.revokedReason === 'app_revoked') {
        // The app revoked it; this approved request is the user's full consent to bring it back.
        await tx.tinyCloudNativeStepUp.update({ where: { id: existing.id },
          data: { status: 'ACTIVE', revokedAt: null, revokedReason: null, approvedPermissions: permissions, approvedAt, lastRenewedAt: null } });
      } else invalidGrant('the step-up was revoked with its grant');

      return {
        tinycloud_stepup: {
          version: 1,
          appId,
          grantId: grant.id,
          address: delegation.address,
          chainId: delegation.chainId,
          ownerDid: delegation.ownerDid,
          spaces: [...new Set(permissions.map((permission) => permission.space))].map((space) => ({ space, spaceId: `tinycloud:pkh:eip155:1:${delegation.address}:${space}` })),
          verificationMethod: delegation.verificationMethod,
          siwe: delegation.siwe,
          signature: delegation.signature,
          delegationHeader: delegation.delegationHeader,
          delegationCid: delegation.delegationCid,
          issuedAt: delegation.issuedAt,
          expiresAt: delegation.expiresAt,
          renewableUntil: new Date(grant.absoluteExpiresAt.getTime() - RENEWAL_CUTOFF_MS).toISOString(),
          permissions: structuredClone(permissions),
          tinycloudHost: delegation.tinycloudHost,
          hosting: 'existing',
        },
      };
    }, { timeout: 15_000 });
  } catch (error) {
    throw spentCodeError(error);
  }
  ctx.setHeader!('Cache-Control', 'no-store');
  ctx.setHeader!('Pragma', 'no-cache');
  return fields;
}

/**
 * The provider's `generateRefreshToken`. Produces the provider's default
 * token and, when this request's code exchange committed a grant, writes the
 * token's stored hash to that grant (`WHERE refreshTokenHash IS NULL`) while
 * the grant is still ACTIVE. Only the grant row is locked, with the same
 * bounded wait as every native transaction.
 */
export async function generateNativeRefreshToken(db: PrismaClient, tokens: ProviderTokenOptions): Promise<string> {
  const token = generateRandomString(32, 'A-Z', 'a-z');
  const grantId = await pendingNativeGrant.get();
  if (grantId === undefined) return token;
  await pendingNativeGrant.set(undefined);
  const refreshTokenHash = await storedToken(tokens, token, 'refresh_token');
  let linked: number;
  try {
    linked = await db.$transaction(async (tx) => {
      await tx.$executeRaw`SET LOCAL lock_timeout = '5s'`;
      const updated = await tx.tinyCloudNativeGrant.updateMany({
        where: { id: grantId, refreshTokenHash: null, status: 'ACTIVE' },
        data: { refreshTokenHash },
      });
      return updated.count;
    }, { timeout: 15_000 });
  } catch (error) {
    throw spentCodeError(error);
  }
  if (linked !== 1) invalidGrant('native grant is no longer active; the authorization code is already spent, start a new authorization');
  return token;
}

/**
 * The client better-auth writes through. The token guard triggers
 * (20261007_0003) refuse a token row for a native grant that is no longer
 * ACTIVE; without this the provider's insert failure would be a bare 500.
 * Only the two token inserts are intercepted.
 */
export function withNativeTokenGuardErrors(db: PrismaClient): PrismaClient {
  const create = async ({ args, query }: { args: unknown; query: (args: unknown) => Promise<unknown> }) => {
    try {
      return await query(args);
    } catch (error) {
      throw spentCodeError(error);
    }
  };
  // A query-only extension keeps the client's model surface unchanged.
  return db.$extends({ query: { oauthRefreshToken: { create }, oauthAccessToken: { create } } }) as unknown as PrismaClient;
}
