import { randomBytes } from 'node:crypto';
import { APIError } from 'better-auth/api';
import { generateRandomString } from 'better-auth/crypto';
import { defineRequestState, getCurrentAuthContext } from '@better-auth/core/context';
import type { PrismaClient } from '@openkey/db';
import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { isNativeDelegationLockTimeout } from './errors';
import { enabledNativeDelegation } from './policy';
import { storedToken, type ProviderTokenOptions } from './provider-tokens';
import { OPENKEY_SESSION_PROOF_HEADER } from './public-protocol';
import { verifySessionProof } from './session-proof';
import type { NativePermission } from './par';

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
 * renewal refuses.
 */

const RENEWAL_CUTOFF_MS = 300_000;
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

export interface NativeCodeExchangeInput {
  user?: { id: string } | null;
  scopes: string[];
  verificationValue?: { query?: object } | null;
}

function invalidGrant(description: string): never {
  throw new APIError('BAD_REQUEST', { error: 'invalid_grant', error_description: description });
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

  const requestId = query.tinycloud_request;
  if (typeof requestId !== 'string' || !requestId) invalidGrant('authorization code has no native delegation request');
  const request = await db.tinyCloudNativeRequest.findUnique({ where: { id: requestId } });
  if (!request) invalidGrant('no approved native delegation request for this code');
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

  const ctx = await getCurrentAuthContext();
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

      const now = Date.now();
      const absoluteExpiresAt = new Date(now + ceiling.grantLifetimeSeconds * 1000);
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
            renewableUntil: new Date(absoluteExpiresAt.getTime() - RENEWAL_CUTOFF_MS).toISOString(),
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
    if (isNativeDelegationLockTimeout(error)) {
      throw new APIError('SERVICE_UNAVAILABLE', {
        error: 'temporarily_unavailable',
        error_description: 'lock contention; the authorization code is already spent and cannot be retried, start a new authorization',
      }, { 'Retry-After': '2' });
    }
    throw error;
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
 * The provider's `generateRefreshToken`. Produces the provider's default
 * token and, when this request's code exchange committed a grant, writes the
 * token's stored hash to that grant (`WHERE refreshTokenHash IS NULL`).
 */
export async function generateNativeRefreshToken(db: PrismaClient, tokens: ProviderTokenOptions): Promise<string> {
  const token = generateRandomString(32, 'A-Z', 'a-z');
  const grantId = await pendingNativeGrant.get();
  if (grantId === undefined) return token;
  await pendingNativeGrant.set(undefined);
  const linked = await db.tinyCloudNativeGrant.updateMany({
    where: { id: grantId, refreshTokenHash: null },
    data: { refreshTokenHash: await storedToken(tokens, token, 'refresh_token') },
  });
  if (linked.count !== 1) invalidGrant('native grant could not be linked to its refresh token');
  return token;
}
