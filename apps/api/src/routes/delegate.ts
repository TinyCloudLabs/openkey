// Delegate route - creates TinyCloud delegation for CLI auth flow
import { randomUUID } from 'node:crypto';
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { createTeeClient, unseal } from '@openkey/tee';
import { requireSession } from '../middleware/session';
import {
  createDelegateSignerAuth,
  type DelegateSignerContext,
} from '../middleware/delegate-signer-auth';
import type { Hex } from 'viem';
import {
  prepareSession,
  completeSessionSetup,
  ensureEip55,
  generateHostSIWEMessage,
  makeSpaceId,
} from '@tinycloud/node-sdk-wasm';
import { activateSessionWithHost } from '@tinycloud/sdk-core';
import { CAPABILITIES } from '@tinycloud/bootstrap';
import {
  delegateErrorResponse,
  normalizeDelegateReason,
  resolvePreparedExpirationTime,
} from './delegate-validation';
import {
  DEFAULT_ABILITIES,
  SIWE_DOMAIN,
  abilitiesFromPermissions,
  assertBaselineSubset,
  assertRequiredActions,
  normalizeStringArray,
  parsePreparedRecap,
  prepareDelegationSession,
  type DelegationJwk,
  type DelegationPermissionEntry,
  type RecapEntry,
} from './delegate-session';

// Re-export the pure delegation helpers so existing external test files
// (e.g. delegate-oauth-route.test.ts) that import them from this module
// keep working.
export {
  prepareDelegationSession,
  assertBaselineSubset,
  assertDefaultSubset,
  DEFAULT_ABILITIES,
} from './delegate-session';
import {
  evaluateAutoSignPolicy,
  evaluateBootstrapSigningScope,
} from './delegate-autosign';
import { deriveKeyForRecord } from '../services/key-sealing';
import {
  canonicalizeCoordinationosOrigin,
  evaluateCoordinationosSessionRequest,
  sha256Hex,
  type CoordinationosPolicyEvidence,
} from '../services/coordinationos-session-policy';
import {
  consumeCoordinationosGrant,
  coordinationosDenialResponse,
  coordinationosStatus,
  recordCoordinationosDenial,
  recordCoordinationosSignerError,
  sparseCoordinationosEvidence,
  type CoordinationosDenialCode,
} from '../services/coordinationos-signing-audit';

const prisma = createPrismaClient();
const tee = createTeeClient();

async function resolveBetterAuthSession(c: any): Promise<boolean> {
  let resolved = false;
  await (requireSession as any)(c, async () => {
    resolved = true;
  });
  return resolved;
}

const defaultDelegateSignerAuth = createDelegateSignerAuth({
  database: prisma,
  resolveSession: resolveBetterAuthSession,
});
let activeDelegateSignerAuth = defaultDelegateSignerAuth;

export function setDelegateSignerAuthMiddlewareForTests(
  middleware = defaultDelegateSignerAuth,
): void {
  activeDelegateSignerAuth = middleware;
}

export const delegateRouter = new Hono<DelegateSignerContext>();

// Only the signer route accepts the narrow CoordinationOS OAuth principal.
// Every other delegate endpoint retains the existing Better Auth session gate.
delegateRouter.use('*', async (c, next) => {
  if (c.req.path.endsWith('/sign')) {
    return activeDelegateSignerAuth(c, next);
  }
  return (requireSession as any)(c, next);
});

// Route-layer alias for the CLI permission entry shape. Keeps existing route
// bodies using their historical local type name while the actual definition
// lives in delegate-session.ts.
type PermissionEntry = DelegationPermissionEntry;

interface OpenKeySigningRequestBody {
  address: string;
  chainId: number;
  message: string;
  type: 'siwe' | 'message';
  keyId?: string;
  purpose?: string;
}

/**
 * Default lifetime when callers don't specify one. Tuned to match the
 * client-side default in `@tinycloud/cli` so an agent can run unattended
 * for the same window whether it's signing locally or coming through
 * OpenKey.
 */
const DEFAULT_DELEGATION_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
/**
 * Upper bound on caller-supplied expiry. Ten years is effectively "forever"
 * — calls that ask for more get clamped here. The constant exists primarily
 * to guard against integer overflow / silly inputs, not as a security policy
 * lever. Long-lived agents and API-token-style delegations are first-class
 * use cases; revocation, not expiry, is the right control for them.
 */
const MAX_DELEGATION_EXPIRY_MS = 10 * 365 * 24 * 60 * 60 * 1000;
const MIN_DELEGATION_EXPIRY_MS = 60 * 1000; // 1 minute

const MS_UNIT_FACTORS: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
  w: 7 * 24 * 60 * 60 * 1000,
};

/**
 * Parse a caller-provided expiry into a clamped ms count.
 *  - missing → default (7d)
 *  - number → treated as raw milliseconds
 *  - "604800000" → numeric milliseconds
 *  - "7d", "30m", "12h", "1w" → ms-format string (small subset of
 *    the popular `ms` package, inlined to avoid a new dep)
 *
 * Result is clamped to [MIN, MAX]. Bad input throws a 400-friendly Error.
 */
function resolveDelegationExpiryMs(input: unknown): number {
  if (input === undefined || input === null || input === '') {
    return DEFAULT_DELEGATION_EXPIRY_MS;
  }
  let raw: number;
  if (typeof input === 'number') {
    raw = input;
  } else if (typeof input === 'string') {
    const trimmed = input.trim();
    if (/^\d+$/.test(trimmed)) {
      raw = Number(trimmed);
    } else {
      const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)$/i);
      if (!match) {
        throw new Error(`Invalid expiry "${input}" — use ms-format ("7d", "30m") or a millisecond integer.`);
      }
      const valueText = match[1];
      const unit = match[2]?.toLowerCase();
      const factor = unit ? MS_UNIT_FACTORS[unit] : undefined;
      if (!valueText || factor === undefined) {
        throw new Error(`Invalid expiry "${input}" — use ms-format ("7d", "30m") or a millisecond integer.`);
      }
      const value = Number(valueText);
      raw = value * factor;
    }
  } else {
    throw new Error(`expiry must be a string or number, got ${typeof input}`);
  }
  if (!Number.isFinite(raw) || raw <= 0) {
    throw new Error(`expiry must be a positive number, got ${input}`);
  }
  return Math.min(MAX_DELEGATION_EXPIRY_MS, Math.max(MIN_DELEGATION_EXPIRY_MS, raw));
}

function validatePermissions(permissions: unknown): PermissionEntry[] {
  if (!Array.isArray(permissions) || permissions.length === 0) {
    throw new Error('permissions must be a non-empty array');
  }
  return permissions.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`permissions[${index}] is not an object`);
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.service !== 'string' || !e.service) {
      throw new Error(`permissions[${index}].service is required`);
    }
    const isRawEncryption = e.service === 'tinycloud.encryption' &&
      typeof e.path === 'string' &&
      e.path.startsWith('urn:tinycloud:encryption:');
    if (!isRawEncryption && (typeof e.space !== 'string' || !e.space)) {
      throw new Error(`permissions[${index}].space is required`);
    }
    if (e.space !== undefined && typeof e.space !== 'string') {
      throw new Error(`permissions[${index}].space must be a string`);
    }
    if (typeof e.path !== 'string') {
      throw new Error(`permissions[${index}].path must be a string`);
    }
    if (!Array.isArray(e.actions) || e.actions.some((a) => typeof a !== 'string')) {
      throw new Error(`permissions[${index}].actions must be a string[]`);
    }
    return {
      service: e.service,
      ...(typeof e.space === 'string' ? { space: e.space } : {}),
      path: e.path,
      actions: e.actions as string[],
    };
  });
}

function isOpenKeySigningRequestBody(body: unknown): body is OpenKeySigningRequestBody {
  if (!body || typeof body !== 'object') return false;

  const candidate = body as Record<string, unknown>;
  return (
    typeof candidate.address === 'string' &&
    Number.isSafeInteger(candidate.chainId) &&
    typeof candidate.message === 'string' &&
    (candidate.type === 'siwe' || candidate.type === 'message') &&
    (candidate.keyId === undefined || typeof candidate.keyId === 'string')
  );
}

function openKeyApprovalRequired(reason: string, code: string) {
  return {
    approved: false,
    needsApproval: true,
    reason,
    code,
  };
}

async function unsealManagedKey(
  key: { userId: string | null; sealingContext?: string | null },
  sealedBlob: string,
): Promise<Hex> {
  const sealingKey = await deriveKeyForRecord(tee, key);
  return unseal(sealedBlob, sealingKey) as Promise<Hex>;
}

async function signManagedKey(
  key: { userId: string | null; sealingContext?: string | null },
  sealedBlob: string,
  message: string,
) {
  const privateKey = await unsealManagedKey(key, sealedBlob);
  return signWithManagedPrivateKey(privateKey, message);
}

async function signWithManagedPrivateKey(privateKey: Hex, message: string) {
  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  const account = createWalletFromPrivateKey(privateKey);
  return account.signMessage({ message });
}

function coordinationosBootstrapTrigger(address: string): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: SIWE_DOMAIN,
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: makeSpaceId(address, 1, 'account'),
    jwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
    abilities: {
      capabilities: {
        capabilities: [CAPABILITIES.READ],
      },
    },
  }).siwe;
}

/**
 * POST /api/delegate/sign
 *
 * SDK OpenKey callback signing contract:
 * request `{ address, chainId, message, type, keyId? }`;
 * response `{ approved: true, signature }` or `{ approved: false, ... }`.
 *
 * This is the zero-gesture Auto-Sign path. The normal delegate routes below
 * remain explicit-approval flows and deliberately do not apply this gate.
 */
delegateRouter.post('/sign', async (c) => {
  const principal = c.get('delegateSignerPrincipal');
  const authFailure = c.get('delegateSignerAuthFailure');
  const oauthContext = c.get('delegateSignerOauthContext');
  const requestId = randomUUID();

  const auditDenial = async (
    code: CoordinationosDenialCode,
    evidence: CoordinationosPolicyEvidence,
  ) => {
    try {
      const decision = await recordCoordinationosDenial(prisma, code, evidence, requestId);
      return c.json(
        coordinationosDenialResponse(code, decision.decisionId),
        coordinationosStatus(code) as any,
      );
    } catch {
      return c.json(
        coordinationosDenialResponse('audit_write_failed', 'unavailable'),
        500,
      );
    }
  };

  if (!principal) {
    const code = authFailure?.code ?? 'missing_authorization';
    return auditDenial(code, sparseCoordinationosEvidence({
      oauthAccessTokenId: authFailure?.oauthAccessTokenId,
      tokenDigest: authFailure?.tokenDigest,
      clientId: authFailure?.clientId,
      userId: authFailure?.userId,
    }));
  }

  if (principal.kind === 'coordinationos-oauth') {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return auditDenial('malformed_json', sparseCoordinationosEvidence({
        oauthAccessTokenId: principal.oauthAccessTokenId,
        tokenDigest: principal.tokenDigest,
        clientId: principal.clientId,
        userId: principal.userId,
      }));
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return auditDenial('malformed_json', sparseCoordinationosEvidence({
        oauthAccessTokenId: principal.oauthAccessTokenId,
        tokenDigest: principal.tokenDigest,
        clientId: principal.clientId,
        userId: principal.userId,
      }));
    }
    const candidate = body as Record<string, unknown>;
    const required = ['address', 'chainId', 'message', 'type', 'purpose', 'keyId'] as const;
    if (required.some((field) => !Object.prototype.hasOwnProperty.call(candidate, field))) {
      return auditDenial('missing_field', sparseCoordinationosEvidence({
        oauthAccessTokenId: principal.oauthAccessTokenId,
        tokenDigest: principal.tokenDigest,
        clientId: principal.clientId,
        userId: principal.userId,
        keyId: typeof candidate.keyId === 'string' ? candidate.keyId : null,
        origin: canonicalizeCoordinationosOrigin(c.req.header('origin')),
        chainId: typeof candidate.chainId === 'number' ? candidate.chainId : null,
        purpose: typeof candidate.purpose === 'string' ? candidate.purpose : null,
        type: typeof candidate.type === 'string' ? candidate.type : null,
        siweDigest: typeof candidate.message === 'string' ? sha256Hex(candidate.message) : null,
      }));
    }

    const key = typeof candidate.keyId === 'string'
      ? await prisma.ethereumKey.findUnique({
          where: { id: candidate.keyId },
          select: {
            id: true,
            userId: true,
            address: true,
            keyType: true,
            keyPurpose: true,
            archivedAt: true,
            sealedBlob: true,
            sealingContext: true,
          },
        })
      : null;
    const policy = evaluateCoordinationosSessionRequest({
      principal,
      client: oauthContext?.client ?? null,
      user: oauthContext?.user ?? null,
      key,
      request: {
        address: candidate.address,
        chainId: candidate.chainId,
        message: candidate.message,
        type: candidate.type,
        purpose: candidate.purpose,
        keyId: candidate.keyId,
        origin: c.req.header('origin') ?? null,
      },
    });
    if (!policy.allowed) return auditDenial(policy.code, policy.evidence);
    if (!key || !key.sealedBlob || !policy.evidence.nonceDigest) {
      return auditDenial('key_unavailable', policy.evidence);
    }

    let grant;
    try {
      grant = await consumeCoordinationosGrant(prisma, {
        evidence: policy.evidence,
        oauthAccessTokenId: principal.oauthAccessTokenId,
        nonceDigest: policy.evidence.nonceDigest,
        clientId: principal.clientId,
        userId: principal.userId,
        keyId: key.id,
        requestId,
      });
    } catch {
      return c.json(
        coordinationosDenialResponse('audit_write_failed', 'unavailable'),
        500,
      );
    }
    if (!grant.allowed) {
      return c.json(
        coordinationosDenialResponse(grant.code, grant.decision.decisionId),
        coordinationosStatus(grant.code) as any,
      );
    }

    try {
      const privateKey = await unsealManagedKey(key, key.sealedBlob);
      const { ensureTinyCloudBootstrapForApprovedSign } = await import(
        '../services/tinycloud-bootstrap'
      );
      const bootstrap = await ensureTinyCloudBootstrapForApprovedSign({
        // The OAuth grant is already a policy-approved signing decision. The
        // bootstrap service's user-preference lookup is for the unchanged
        // Better Auth session branch, so satisfy that narrow seam without
        // mutating the user's stored Auto-Sign preference.
        prisma: {
          user: {
            findUnique: async () => ({ autoSignEnabled: true }),
          },
          tinyCloudBootstrapState: prisma.tinyCloudBootstrapState,
        } as any,
        userId: principal.userId,
        key: {
          id: key.id,
          address: key.address,
          keyType: key.keyType,
          keyPurpose: 'PERSONAL',
        },
        privateKey,
        message: coordinationosBootstrapTrigger(key.address),
        format: 'personal_sign',
      });
      if (bootstrap.status !== 'complete') {
        throw new Error('TinyCloud bootstrap did not complete');
      }
      const signature = await signWithManagedPrivateKey(
        privateKey,
        candidate.message as string,
      );
      return c.json({
        approved: true,
        signature,
        decisionId: grant.decision.decisionId,
        policyVersion: grant.decision.policyVersion,
      });
    } catch {
      try {
        const decision = await recordCoordinationosSignerError(prisma, policy.evidence, requestId);
        return c.json(
          coordinationosDenialResponse('signer_failed', decision.decisionId),
          500,
        );
      } catch {
        return c.json(
          coordinationosDenialResponse('audit_write_failed', 'unavailable'),
          500,
        );
      }
    }
  }

  const user = c.get('user');
  const body = await c.req.json();

  if (!isOpenKeySigningRequestBody(body)) {
    return c.json({
      approved: false,
      reason: 'address, chainId, message, and type are required',
    }, 400);
  }

  let address: string;
  try {
    address = ensureEip55(body.address);
  } catch {
    return c.json({
      approved: false,
      reason: 'address must be a valid EVM address',
    }, 400);
  }

  if (body.chainId <= 0) {
    return c.json({
      approved: false,
      reason: 'chainId must be a positive EIP-155 chain ID',
    }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: {
      userId: user.id,
      keyPurpose: 'PERSONAL',
      archivedAt: null,
      ...(body.keyId
        ? { id: body.keyId }
        : { address, keyType: 'MANAGED' as const }),
    },
  });

  if (!key) {
    return c.json({ approved: false, reason: 'Managed key not found' }, 404);
  }

  if (ensureEip55(key.address) !== address) {
    return c.json({
      approved: false,
      reason: 'Requested address does not match the managed key',
    }, 403);
  }

  if (key.keyType !== 'MANAGED') {
    return c.json({
      approved: false,
      reason: 'Only managed keys can be used with this endpoint',
    }, 400);
  }

  if (!key.sealedBlob) {
    return c.json({ approved: false, reason: 'Key has no sealed data' }, 400);
  }

  const autoSignPreference = await prisma.user.findUnique({
    where: { id: user.id },
    select: { autoSignEnabled: true },
  });

  if (!autoSignPreference) {
    return c.json({ approved: false, reason: 'User not found' }, 404);
  }

  let entries: RecapEntry[];
  try {
    entries = parsePreparedRecap(body.message);
  } catch {
    return c.json(openKeyApprovalRequired(
      'OpenKey Auto-Sign only supports bootstrap SIWE/ReCap signing requests',
      'outside_bootstrap_allowlist',
    ));
  }

  const autoSignDecision = evaluateAutoSignPolicy(
    autoSignPreference.autoSignEnabled,
    evaluateBootstrapSigningScope({
      entries,
      address,
      chainId: body.chainId,
    }),
  );

  if (!autoSignDecision.allowed) {
    return c.json(openKeyApprovalRequired(autoSignDecision.reason, autoSignDecision.code));
  }

  const signature = await signManagedKey(key, key.sealedBlob, body.message);
  return c.json({
    approved: true,
    signature,
  });
});

/**
 * POST /api/delegate/host
 *
 * Signs a TinyCloud space/host SIWE for a managed key. This is the root-key
 * half of bootstrap space hosting; the caller submits the signed SIWE to the
 * node's /delegate endpoint.
 */
delegateRouter.post('/host', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    peerId: string;
    space?: string;
    prefix?: string;
  }>();

  if (!body.keyId || !body.peerId) {
    return c.json({ error: 'keyId and peerId are required' }, 400);
  }

  const spacePrefix = body.space || body.prefix;
  if (!spacePrefix) {
    return c.json({ error: 'space is required' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id, keyPurpose: 'PERSONAL', archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType !== 'MANAGED') {
    return c.json({ error: 'Only managed keys can be used with this endpoint.' }, 400);
  }

  if (!key.sealedBlob) {
    return c.json({ error: 'Key has no sealed data' }, 400);
  }

  const address = ensureEip55(key.address);
  const chainId = 1;
  const normalizedSpace = spacePrefix.startsWith('tinycloud:')
    ? spacePrefix.slice(spacePrefix.lastIndexOf(':') + 1)
    : spacePrefix;
  const spaceId = makeSpaceId(address, chainId, normalizedSpace);
  const issuedAt = new Date().toISOString();
  const siwe = generateHostSIWEMessage({
    address,
    chainId,
    domain: SIWE_DOMAIN,
    issuedAt,
    spaceId,
    peerId: body.peerId,
  });

  const signature = await signManagedKey(key, key.sealedBlob, siwe);
  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;

  return c.json({
    siwe,
    signature,
    spaceId,
    ownerDid,
    address,
    chainId,
    peerId: body.peerId,
  });
});

/**
 * POST /api/delegate
 *
 * Creates a TinyCloud delegation for the CLI using a MANAGED key.
 * The server unseals the private key via TEE and signs the SIWE message.
 */
delegateRouter.post('/', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    jwk: DelegationJwk;
    host: string;
    prefix?: string;
    actionKeys?: unknown;
    permissionKeys?: unknown;
    permissions?: unknown;
    expiry?: unknown;
    reason?: unknown;
  }>();

  if (!body.keyId || !body.jwk || !body.host) {
    return c.json({ error: 'keyId, jwk, and host are required' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id, keyPurpose: 'PERSONAL', archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType !== 'MANAGED') {
    return c.json({ error: 'Only managed keys can be used with this endpoint. Use /api/delegate/prepare + /api/delegate/complete for external keys.' }, 400);
  }

  if (!key.sealedBlob) {
    return c.json({ error: 'Key has no sealed data' }, 400);
  }

  const address = ensureEip55(key.address);
  const chainId = 1;
  const prefix = body.prefix || 'default';
  const host = body.host;
  const reason = normalizeDelegateReason(body.reason);
  let permissions: PermissionEntry[] | undefined;
  if (body.permissions !== undefined) {
    try {
      permissions = validatePermissions(body.permissions);
    } catch (err) {
      return c.json(delegateErrorResponse(err, 'Invalid permissions', 'invalid_permissions'), 400);
    }
  }
  let expiryMs: number;
  try {
    expiryMs = resolveDelegationExpiryMs(body.expiry);
  } catch (err) {
    return c.json(delegateErrorResponse(err, 'Invalid expiry', 'invalid_expiry'), 400);
  }
  let preparedResult: ReturnType<typeof prepareDelegationSession>;
  try {
    preparedResult = prepareDelegationSession({
      address,
      chainId,
      prefix,
      jwk: body.jwk,
      actionKeys: normalizeStringArray(body.actionKeys, 'actionKeys'),
      permissionKeys: normalizeStringArray(body.permissionKeys, 'permissionKeys'),
      permissions,
      expiryMs,
    });
  } catch (e) {
    return c.json(delegateErrorResponse(e, 'Failed to prepare delegation', 'delegation_prepare_failed'), 400);
  }

  const expirationTime = resolvePreparedExpirationTime(preparedResult.prepared);
  if (!expirationTime) {
    return c.json({ error: 'prepared session must include a valid expirationTime or SIWE Expiration Time' }, 400);
  }

  const signature = await signManagedKey(key, key.sealedBlob, preparedResult.prepared.siwe);

  const session = completeSessionSetup({
    ...preparedResult.prepared,
    signature,
  });

  let hostActivated = false;
  try {
    const activationResult = await activateSessionWithHost(host, session.delegationHeader);
    hostActivated = activationResult.success;
    if (!hostActivated) {
      console.warn(`[Delegate] Session activation warning: ${activationResult.error}`);
    }
  } catch (e) {
    console.warn(`[Delegate] Session activation failed (host unreachable):`, e);
  }

  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;

  return c.json({
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId: preparedResult.spaceId,
    ownerDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
    hostActivated,
    edited: preparedResult.edited,
    reason,
    expirationTime,
    expiresAt: expirationTime,
    expiry: expirationTime,
    // Include the SIWE message so callers (CLI, web SDK) can persist it
    // alongside the delegation. The SDK extracts `expirationTime` from
    // this string at session-restore time; without it, restored sessions
    // are treated as expired-at-epoch-zero.
    siwe: preparedResult.prepared.siwe,
  });
});

/**
 * POST /api/delegate/prepare
 *
 * Prepares a SIWE delegation message for an external key to sign.
 * Returns the SIWE message and prepared session data. The client
 * signs the SIWE message with their browser wallet, then calls
 * POST /api/delegate/complete with the signature.
 */
delegateRouter.post('/prepare', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    jwk: DelegationJwk;
    host: string;
    prefix?: string;
    actionKeys?: unknown;
    permissionKeys?: unknown;
    permissions?: unknown;
    expiry?: unknown;
    reason?: unknown;
  }>();

  if (!body.keyId || !body.jwk || !body.host) {
    return c.json({ error: 'keyId, jwk, and host are required' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id, keyPurpose: 'PERSONAL', archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  const address = ensureEip55(key.address);
  const chainId = 1;
  const prefix = body.prefix || 'default';
  const host = body.host;
  const reason = normalizeDelegateReason(body.reason);
  let permissions: PermissionEntry[] | undefined;
  if (body.permissions !== undefined) {
    try {
      permissions = validatePermissions(body.permissions);
    } catch (err) {
      return c.json(delegateErrorResponse(err, 'Invalid permissions', 'invalid_permissions'), 400);
    }
  }
  let expiryMs: number;
  try {
    expiryMs = resolveDelegationExpiryMs(body.expiry);
  } catch (err) {
    return c.json(delegateErrorResponse(err, 'Invalid expiry', 'invalid_expiry'), 400);
  }
  let preparedResult: ReturnType<typeof prepareDelegationSession>;
  try {
    preparedResult = prepareDelegationSession({
      address,
      chainId,
      prefix,
      jwk: body.jwk,
      actionKeys: normalizeStringArray(body.actionKeys, 'actionKeys'),
      permissionKeys: normalizeStringArray(body.permissionKeys, 'permissionKeys'),
      permissions,
      expiryMs,
    });
  } catch (e) {
    return c.json(delegateErrorResponse(e, 'Failed to prepare delegation', 'delegation_prepare_failed'), 400);
  }

  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;

  // Ensure JWK is preserved as a plain object through JSON round-trip.
  // The WASM prepareSession may return JWK as a special object that
  // doesn't serialize correctly, so we merge the original JWK back in.
  const preparedData = {
    ...preparedResult.prepared,
    jwk: body.jwk,
  };

  return c.json({
    prepared: preparedData,
    spaceId: preparedResult.spaceId,
    ownerDid,
    address,
    chainId,
    host,
    jwk: body.jwk,
    permissions: preparedResult.permissions,
    selectedActionKeys: preparedResult.selectedActionKeys,
    edited: preparedResult.edited,
    reason,
  });
});

/**
 * POST /api/delegate/complete
 *
 * Completes a delegation using a wallet-signed SIWE message.
 * Takes the prepared session data from /prepare plus the signature,
 * calls completeSessionSetup, activates the session, and returns
 * the delegation data.
 */
delegateRouter.post('/complete', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    prepared: any;
    signature: string;
    host: string;
    jwk: DelegationJwk;
    edited?: boolean;
    reason?: unknown;
    /**
     * The CLI-supplied permissions that were the baseline for /prepare.
     * When present, this is used instead of DEFAULT_ABILITIES for the
     * subset check that guards against a compromised frontend crafting a
     * broader SIWE. Optional; falls back to DEFAULT_ABILITIES when absent.
     */
    permissions?: unknown;
  }>();

  if (!body.prepared || !body.signature || !body.host || !body.jwk) {
    return c.json({ error: 'prepared, signature, host, and jwk are required' }, 400);
  }

  let baselinePermissions: PermissionEntry[] | undefined;
  if (body.permissions !== undefined) {
    try {
      baselinePermissions = validatePermissions(body.permissions);
    } catch (err) {
      return c.json(delegateErrorResponse(err, 'Invalid permissions', 'invalid_permissions'), 400);
    }
  }

  if (body.edited) {
    try {
      const entries = parsePreparedRecap(body.prepared.siwe || '');
      const baseline = baselinePermissions
        ? abilitiesFromPermissions(baselinePermissions)
        : DEFAULT_ABILITIES;
      assertBaselineSubset(entries, baseline);
      assertRequiredActions(entries);
    } catch (e) {
      return c.json({ error: e instanceof Error ? e.message : 'Invalid edited permissions' }, 400);
    }
  }

  const expirationTime = resolvePreparedExpirationTime(body.prepared);
  if (!expirationTime) {
    return c.json({ error: 'prepared session must include a valid expirationTime or SIWE Expiration Time' }, 400);
  }

  // Ensure JWK is a proper object with kty for WASM deserialization
  const session = completeSessionSetup({
    ...body.prepared,
    jwk: body.jwk,
    signature: body.signature,
  });

  let hostActivated = false;
  try {
    const activationResult = await activateSessionWithHost(body.host, session.delegationHeader);
    hostActivated = activationResult.success;
    if (!hostActivated) {
      console.warn(`[Delegate] Session activation warning: ${activationResult.error}`);
    }
  } catch (e) {
    console.warn(`[Delegate] Session activation failed (host unreachable):`, e);
  }

  // Extract address/chainId from the prepared data
  const address = body.prepared.address || '';
  const chainId = body.prepared.chainId || 1;
  const spaceId = body.prepared.spaceId || '';
  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;
  const reason = normalizeDelegateReason(body.reason);

  return c.json({
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId,
    ownerDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
    hostActivated,
    edited: Boolean(body.edited),
    reason,
    expirationTime,
    expiresAt: expirationTime,
    expiry: expirationTime,
    // Echo the SIWE the caller asked us to sign — the SDK extracts
    // `expirationTime` from this when restoring the session, and
    // without it a restored session is treated as expired-at-epoch-zero.
    siwe: body.prepared.siwe,
  });
});
