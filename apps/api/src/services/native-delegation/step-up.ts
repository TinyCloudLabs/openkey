import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';
import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { TINYCLOUD_DELEGATED_PATH, TINYCLOUD_DELEGATED_PATH_MAX_LENGTH, hasDotSegment } from '../tinycloud-path-policy';
import { sameTinyCloudHost } from '../tinycloud-hosts';
import { lockNativeReviewer } from '../reviewer-native';
import { nativeDelegationLockResponse } from './errors';
import { REQUEST_URI_PREFIX } from './par';
import { enabledNativeDelegation, STEP_UP_SPACES, type NativeStepUpCeilings, type NativeStepUpSpace } from './policy';
import { NATIVE_DELEGATION_ENDPOINT_PATHS, OPENKEY_SESSION_PROOF_HEADER, nativeStepUpEnabled } from './public-protocol';
import { startSessionProofJtiSweep } from './renew-revoke';
import { credentialHash, SESSION_PROOF_MAX_SKEW_SECONDS, sessionProofJtiHash, verifySessionProofClaims } from './session-proof';

/**
 * Step-up request (TC-3569, spec: "Step-up"). The Home refresh token plus an
 * `OpenKey-Session-Proof` over it authorize a request to add one framed app's
 * read-only entries, in spaces beyond the sign-in grant's own, to the existing
 * grant. The request carries only what the user will be shown and sign; the
 * delegate key is read from the grant and is never accepted from the caller.
 * The refresh token is neither rotated nor consumed.
 *
 * This endpoint only records a `STEPUP` request and returns a `request_uri`
 * for the ordinary `/authorize` step. Nothing is signed or stored as a
 * step-up here.
 */

const FORM_KEYS = new Set(['client_id', 'refresh_token', 'app_id', 'permissions', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method']);
const APP_ID = /^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$/;
const ENTRY_KEYS = new Set(['service', 'space', 'path', 'actions']);
const KV_ACTIONS = ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata'];
const SQL_ACTIONS = ['tinycloud.sql/read', 'tinycloud.sql/schema'];
const MAX_ENTRIES = 32;
const MAX_PENDING_PER_GRANT = 8;
/** The last moment a grant can be used, as for renewal (`renew-revoke.ts`): its absolute expiry less 300 s. */
const GRANT_CUTOFF_MS = 300_000;
const REQUEST_URI_TTL_MS = 90_000;
const REQUEST_TTL_MS = 600_000;

export type StepUpPermission = {
  service: 'tinycloud.kv' | 'tinycloud.sql';
  space: NativeStepUpSpace;
  path: string;
  actions: string[];
};

/** Why an entry set was refused: `malformed` is a client bug, `ceiling` is policy. */
export class StepUpEntryError extends Error {
  constructor(readonly kind: 'malformed' | 'ceiling', message: string) { super(message); }
}

function malformed(message: string): never { throw new StepUpEntryError('malformed', message); }
function beyondCeiling(message: string): never { throw new StepUpEntryError('ceiling', message); }

function covers(allowed: string, path: string): boolean {
  return allowed.endsWith('/') ? path.startsWith(allowed) : path === allowed;
}

/**
 * Validates a step-up entry set against `ceilings[appId]`. App ids and every
 * path are matched exactly and case-sensitively. An entry is accepted only if
 * the ceiling for its space names its service, covers its path (an exact path,
 * or a `/`-terminated prefix) and holds every action. SQL databases are exact
 * names. Duplicate or overlapping entries in one space and service are refused.
 */
export function validateStepUpPermissions(appId: string, value: unknown, ceilings: NativeStepUpCeilings | undefined): StepUpPermission[] {
  if (!APP_ID.test(appId) || appId.length > 128) malformed('invalid app_id');
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ENTRIES) malformed('permissions must be a non-empty array');
  const ceiling = ceilings && Object.hasOwn(ceilings, appId) ? ceilings[appId] : undefined;
  const entries = (value as unknown[]).map((item): StepUpPermission => {
    if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).some((key) => !ENTRY_KEYS.has(key))) malformed('unexpected permission member');
    const entry = item as Record<string, unknown>;
    const { service, space, path, actions } = entry;
    if (typeof service !== 'string' || typeof space !== 'string' || typeof path !== 'string' || !Array.isArray(actions) ||
      actions.length === 0 || actions.some((action) => typeof action !== 'string') || new Set(actions).size !== actions.length) malformed('invalid permission');
    if (!(STEP_UP_SPACES as readonly string[]).includes(space)) malformed('unsupported space');
    const stepUpSpace = space as NativeStepUpSpace;
    const requested = actions as string[];
    if (service === 'tinycloud.kv') {
      if (requested.some((action) => !KV_ACTIONS.includes(action))) malformed('invalid KV action');
      if (path !== '' && (path.length > TINYCLOUD_DELEGATED_PATH_MAX_LENGTH || !TINYCLOUD_DELEGATED_PATH.test(path) || hasDotSegment(path))) malformed('invalid KV path');
      const kv = ceiling?.[stepUpSpace]?.kv;
      if (!kv || !kv.paths.some((allowed) => covers(allowed, path)) ||
        requested.some((action) => !kv.actions.includes(action.slice('tinycloud.kv/'.length)))) beyondCeiling('KV permission exceeds the step-up ceiling');
      return { service, space: stepUpSpace, path, actions: requested };
    }
    if (service === 'tinycloud.sql') {
      if (requested.some((action) => !SQL_ACTIONS.includes(action))) malformed('invalid SQL action');
      if (path.length > TINYCLOUD_DELEGATED_PATH_MAX_LENGTH || !TINYCLOUD_DELEGATED_PATH.test(path) || hasDotSegment(path) || path.endsWith('/')) malformed('invalid SQL database');
      const sql = ceiling?.[stepUpSpace]?.sql;
      if (!sql || !sql.databases.includes(path) ||
        requested.some((action) => !sql.actions.includes(action.slice('tinycloud.sql/'.length)))) beyondCeiling('SQL permission exceeds the step-up ceiling');
      return { service, space: stepUpSpace, path, actions: requested };
    }
    return malformed('unsupported service');
  });
  for (let i = 0; i < entries.length; i++) for (let j = i + 1; j < entries.length; j++) {
    const a = entries[i]!, b = entries[j]!;
    if (a.service === b.service && a.space === b.space &&
      (a.path === b.path || (a.path.endsWith('/') && b.path.startsWith(a.path)) || (b.path.endsWith('/') && a.path.startsWith(b.path)))) malformed('overlapping permissions');
  }
  return entries;
}

type Failure = { error: string; status: 400 | 401 | 404 | 429; retryAfter?: number };

function respondFailure({ error, status, retryAfter }: Failure): Response {
  return Response.json({ error }, {
    status,
    headers: { 'Cache-Control': 'no-store', 'Pragma': 'no-cache', ...(retryAfter ? { 'Retry-After': String(retryAfter) } : {}) },
  });
}

/** Public, cookie-free step-up request endpoint. */
export async function handleNativeStepUpRequest(request: Request, db: PrismaClient, issuer: string): Promise<Response> {
  const fail = (error: string, status: Failure['status'], retryAfter?: number) => respondFailure({ error, status, ...(retryAfter ? { retryAfter } : {}) });
  if (!nativeStepUpEnabled()) return fail('not_found', 404);
  try {
    if ((request.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase() !== 'application/x-www-form-urlencoded') return fail('invalid_request', 400);
    const params = new URLSearchParams(await request.text());
    const keys = [...params.keys()];
    if (new Set(keys).size !== keys.length || keys.some((key) => !FORM_KEYS.has(key)) || [...FORM_KEYS].some((key) => !params.get(key))) return fail('invalid_request', 400);
    const token = params.get('refresh_token')!;
    const hash = credentialHash(token);
    // Only the grant's current refresh token: a rotated-out token is not accepted here.
    const candidate = await db.tinyCloudNativeGrant.findFirst({ where: { refreshTokenHash: hash } });
    if (!candidate || candidate.clientId !== params.get('client_id')) return fail('invalid_session_proof', 401);
    // The proof is checked against the grant's own key, never one supplied here.
    const proof = verifySessionProofClaims(request.headers.get(OPENKEY_SESSION_PROOF_HEADER), {
      sessionJwk: candidate.sessionJwk as { x: string }, sessionJkt: candidate.sessionJkt,
      htu: `${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS.stepup}`, clientId: candidate.clientId, credential: token,
    });
    if (!proof) return fail('invalid_session_proof', 401);
    // Commit the proof's `jti` before any later work, as renew and revoke do.
    const consumed = await db.nativeSessionProofJti.createMany({
      data: [{ jtiHash: sessionProofJtiHash(proof.jti), grantId: candidate.id, expiresAt: new Date((proof.iat + 2 * SESSION_PROOF_MAX_SKEW_SECONDS) * 1000) }],
      skipDuplicates: true,
    });
    if (consumed.count !== 1) return fail('invalid_session_proof', 401);
    await startSessionProofJtiSweep(db);

    const appId = params.get('app_id')!;
    const challenge = params.get('code_challenge')!;
    const state = params.get('state')!;
    if (params.get('code_challenge_method') !== 'S256' || state.length < 16 || state.length > 512 || !/^[A-Za-z0-9_-]{43}$/.test(challenge) ||
      Buffer.from(challenge, 'base64url').length !== 32 || Buffer.from(challenge, 'base64url').toString('base64url') !== challenge) return fail('invalid_request', 400);
    let rawPermissions: unknown;
    try { rawPermissions = JSON.parse(params.get('permissions')!); } catch { return fail('invalid_authorization_details', 400); }

    const result = await db.$transaction(async (tx): Promise<{ failure: Failure } | { requestId: string }> => {
      await tx.$executeRaw`SET LOCAL lock_timeout = '5s'`;
      // Lock order as renewal: reviewer, user, consent, generation, requests, grants.
      const reviewer = await lockNativeReviewer(tx, candidate.userId);
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${candidate.userId} FOR SHARE`;
      const consents = await tx.$queryRaw<{ id: string; scopes: string[] }[]>`
        SELECT id, scopes FROM oauth_consent WHERE "userId" = ${candidate.userId} AND "clientId" = ${candidate.clientId} FOR SHARE`;
      const generations = await tx.$queryRaw<{ generation: bigint }[]>`
        SELECT generation FROM tinycloud_native_consent_generation WHERE "userId" = ${candidate.userId} AND "clientId" = ${candidate.clientId} FOR SHARE`;
      await tx.$queryRaw`SELECT id FROM tinycloud_native_grant WHERE id = ${candidate.id} FOR SHARE`;
      if (Math.abs(Date.now() / 1000 - proof.iat) > SESSION_PROOF_MAX_SKEW_SECONDS) return { failure: { error: 'invalid_session_proof', status: 401 } };
      const grant = await tx.tinyCloudNativeGrant.findUnique({ where: { id: candidate.id } });
      if (!grant || grant.refreshTokenHash !== hash || grant.status !== 'ACTIVE') return { failure: { error: 'invalid_grant', status: 400 } };
      if (!consents.some((consent) => consent.id === grant.consentId && consent.scopes.includes(TINYCLOUD_DELEGATION_SCOPE)) ||
        generations[0]?.generation !== grant.consentGeneration) return { failure: { error: 'consent_required', status: 400 } };
      const now = new Date();
      // Same live and expiry rule as renewal: an expired grant keeps the status ACTIVE.
      if (now.getTime() >= grant.absoluteExpiresAt.getTime() - GRANT_CUTOFF_MS) return { failure: { error: 'consent_required', status: 400 } };
      const user = await tx.user.findUnique({ where: { id: grant.userId }, select: { lockedAt: true, reviewerHoldAt: true } });
      if (!user || user.lockedAt || user.reviewerHoldAt || reviewer) return { failure: { error: 'access_denied', status: 400 } };
      // The token must still be the grant's live refresh token, as for renewal.
      await tx.$queryRaw`SELECT id FROM oauth_refresh_token WHERE token = ${hash} FOR SHARE`;
      const row = await tx.oauthRefreshToken.findUnique({ where: { token: hash } });
      if (!row || row.userId !== grant.userId || row.clientId !== grant.clientId || !row.scopes.includes(TINYCLOUD_DELEGATION_SCOPE) ||
        row.revoked || row.expiresAt <= now) return { failure: { error: 'invalid_grant', status: 400 } };
      const client = await tx.oauthClient.findUnique({ where: { clientId: grant.clientId } });
      const ceiling = client && enabledNativeDelegation(client);
      if (!client || !ceiling || !sameTinyCloudHost(ceiling.tinycloudHost, grant.tinycloudHost)) return { failure: { error: 'consent_required', status: 400 } };
      if (!client.redirectUris.includes(params.get('redirect_uri')!)) return { failure: { error: 'invalid_request', status: 400 } };
      let permissions: StepUpPermission[];
      try { permissions = validateStepUpPermissions(appId, rawPermissions, ceiling.stepUps); }
      catch (error) {
        if (error instanceof StepUpEntryError) return { failure: { error: error.kind === 'ceiling' ? 'access_denied' : 'invalid_authorization_details', status: 400 } };
        throw error;
      }
      const open = await tx.tinyCloudNativeRequest.count({ where: {
        grantId: grant.id, kind: 'STEPUP', status: { in: ['PENDING', 'RESOLVED'] }, expiresAt: { gt: now },
      } });
      if (open >= MAX_PENDING_PER_GRANT) return { failure: { error: 'slow_down', status: 429, retryAfter: 10 } };
      const id = randomBytes(24).toString('base64url');
      await tx.tinyCloudNativeRequest.create({ data: {
        id, kind: 'STEPUP', grantId: grant.id, appId, clientId: grant.clientId, userId: grant.userId,
        redirectUri: params.get('redirect_uri')!, state, codeChallenge: challenge, scopes: [TINYCLOUD_DELEGATION_SCOPE],
        // The delegate is the grant's session key. Nothing in the request can name another.
        sessionDid: grant.sessionDid, sessionJwk: grant.sessionJwk as object, sessionJkt: grant.sessionJkt,
        requestedPermissions: permissions,
        ttlSeconds: Math.min(grant.ttlSeconds, ceiling.maxDelegationTtlSeconds),
        requestUriExpiresAt: new Date(now.getTime() + REQUEST_URI_TTL_MS), expiresAt: new Date(now.getTime() + REQUEST_TTL_MS),
      } });
      return { requestId: id };
    }, { timeout: 15_000 });
    if ('failure' in result) return respondFailure(result.failure);
    return Response.json({ request_uri: REQUEST_URI_PREFIX + result.requestId, expires_in: REQUEST_URI_TTL_MS / 1000 },
      { status: 201, headers: { 'Cache-Control': 'no-store', 'Pragma': 'no-cache' } });
  } catch (error) {
    const locked = nativeDelegationLockResponse(error);
    if (locked) return locked;
    throw error;
  }
}
