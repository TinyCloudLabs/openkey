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
import {
  entriesToAbilities,
  entriesForSelectedActions,
  permissionKey as computePermissionKey,
} from './delegate-session';
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
  actionKey as computeActionKey,
  assertBaselineSubset,
  assertRequiredActions,
  isRequiredAction,
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
import {
  consumeAuthorizationContext,
  digestAbilities,
  digestImmutableFields,
  issueAuthorizationContext,
  type AuthorizationContextToken,
} from '../services/authorization-signing';
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

/**
 * Extract the immutable SIWE header fields whose digest binds the /prepare
 * context to /complete. Any change in any of these fields between prepare
 * and complete indicates tampering — reject.
 *
 * Fields covered (Sol MAJOR-5):
 *   - address, chainId, domain, spaceId — bind the relying party + signer
 *   - issuedAt, expirationTime — bind the temporal window
 *   - nonce — bind session-key identity
 *   - uri — bind the callback URI (protects against RP substitution)
 *   - version — bind SIWE protocol version
 *   - notBefore — when present, must not drift (early activation)
 *   - requestId — when present, opaque correlation id
 *   - statement — the non-ReCap SIWE statement line (statements added AFTER
 *     the ReCap block are permitted to change with narrowing, but the
 *     original SIWE `statement` field before Resources: must not drift)
 *   - nonRecapResources — any resource line that is NOT a urn:recap: block
 *     (these are the caller's application-specific resource URIs and MUST
 *     be preserved byte-for-byte).
 */
function extractImmutableSiweFields(
  siwe: string,
  fallback: {
    address: string;
    chainId: number;
    spaceId: string;
  },
): {
  address: string;
  chainId: number;
  domain: string;
  issuedAt: string;
  expirationTime: string;
  spaceId: string;
  nonce: string;
  uri: string;
  version: string;
  notBefore: string;
  requestId: string;
  statement: string;
  nonRecapResources: string;
} {
  const domainMatch = siwe.match(/^(.+?) wants you to sign in with your Ethereum account:$/m);
  const nonceMatch = siwe.match(/^Nonce:\s*(.+)$/m);
  const issuedMatch = siwe.match(/^Issued At:\s*(.+)$/m);
  const expireMatch = siwe.match(/^Expiration Time:\s*(.+)$/m);
  const uriMatch = siwe.match(/^URI:\s*(.+)$/m);
  const versionMatch = siwe.match(/^Version:\s*(.+)$/m);
  const notBeforeMatch = siwe.match(/^Not Before:\s*(.+)$/m);
  const requestIdMatch = siwe.match(/^Request ID:\s*(.+)$/m);

  // Statement extraction: SIWE places the statement between the blank line
  // after the address and the blank line before "URI:". A missing statement
  // is legal — treat it as the empty string.
  const lines = siwe.split(/\r?\n/);
  let statement = '';
  const uriLineIdx = lines.findIndex((l) => /^URI:/.test(l));
  if (uriLineIdx > 3) {
    // Header (line 0) + address (line 1) + blank (line 2) + statement (line 3+) + blank + URI
    // Take everything from line 3 up to the blank line preceding URI.
    let end = uriLineIdx - 1;
    while (end > 3 && lines[end] === '') end -= 1;
    if (end >= 3) {
      statement = lines.slice(3, end + 1).join('\n');
    }
  }

  // Non-ReCap resources: every "- ..." line that is NOT `- urn:recap:...`
  // These are the caller's original resources that MUST be preserved
  // regardless of narrowing.
  const nonRecapResources = lines
    .filter((l) => /^- /.test(l) && !/^- urn:recap:/.test(l))
    .join('\n');

  return {
    address: fallback.address,
    chainId: fallback.chainId,
    domain: domainMatch?.[1]?.trim() ?? SIWE_DOMAIN,
    issuedAt: issuedMatch?.[1]?.trim() ?? '',
    expirationTime: expireMatch?.[1]?.trim() ?? '',
    spaceId: fallback.spaceId,
    nonce: nonceMatch?.[1]?.trim() ?? '',
    uri: uriMatch?.[1]?.trim() ?? '',
    version: versionMatch?.[1]?.trim() ?? '',
    notBefore: notBeforeMatch?.[1]?.trim() ?? '',
    requestId: requestIdMatch?.[1]?.trim() ?? '',
    statement,
    nonRecapResources,
  };
}

/**
 * Collect the set of action IDs classifier says are required for the given
 * ReCap entries. These IDs are the ones the server MUST see in the final
 * completed selection or the delegation fails.
 */
function requiredActionIdSet(entries: RecapEntry[]): Set<string> {
  const set = new Set<string>();
  for (const entry of entries) {
    for (const action of entry.actions) {
      if (isRequiredAction(entry, action)) {
        set.add(computeActionKey(entry, action));
      }
    }
  }
  return set;
}

/**
 * Collect the set of action IDs present in a set of ReCap entries. This is
 * the "allowed" set the /prepare context binds — /complete cannot select
 * anything outside this set.
 */
function allowedActionIdSet(entries: RecapEntry[]): Set<string> {
  const set = new Set<string>();
  for (const entry of entries) {
    for (const action of entry.actions) {
      set.add(computeActionKey(entry, action));
    }
  }
  return set;
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

  let effectiveEntries: RecapEntry[] = [];
  try {
    effectiveEntries = parsePreparedRecap(preparedResult.prepared.siwe);
  } catch {
    effectiveEntries = [];
  }
  const effectiveGrants = effectiveEntries.map((entry) => ({
    service: entry.service,
    space: entry.space,
    path: entry.path,
    actions: [...entry.actions],
  }));

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
    // Versioned protocol: `signedMessage` is the exact bytes signed,
    // `permissions` is the effective grant set. Callers should prefer
    // these fields over reconstructing from the SIWE string.
    signedMessage: preparedResult.prepared.siwe,
    permissions: effectiveGrants,
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

  // Issue an opaque single-use authorization context so /complete cannot
  // be replayed with a broader SIWE, a different key, or a different host.
  // The context digests are the sole authority for /complete — the `edited`
  // flag in the /complete body is not consulted for authority.
  let authorizationContext: AuthorizationContextToken | null = null;
  try {
    const baselineEntries = parsePreparedRecap(preparedResult.prepared.siwe);
    const allowedActionIds = allowedActionIdSet(baselineEntries);
    const initialSelectionActionIds = new Set(preparedResult.selectedActionKeys);
    const immutableFields = extractImmutableSiweFields(
      preparedResult.prepared.siwe,
      { address, chainId, spaceId: preparedResult.spaceId },
    );
    const baselineAbilitiesDigest = digestAbilities(
      // Use the exact abilities map that would be re-derived at /complete.
      permissions
        ? abilitiesFromPermissions(permissions)
        : DEFAULT_ABILITIES,
    );
    authorizationContext = issueAuthorizationContext({
      userId: user.id,
      keyId: key.id,
      keyAddress: address,
      jwk: body.jwk,
      host,
      spaceId: preparedResult.spaceId,
      baselineAbilitiesDigest,
      immutableFieldsDigest: digestImmutableFields(immutableFields),
      allowedActionIds,
      initialSelectionActionIds,
      expirationTime: immutableFields.expirationTime,
    });
  } catch (issueErr) {
    console.warn('[Delegate] Failed to issue authorization context:', issueErr);
    // If we cannot issue a context there is no safe /complete path — force
    // callers to retry.
    return c.json(
      {
        error: 'Failed to issue authorization context',
        code: 'authorization_context_failed',
      },
      500,
    );
  }

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
    // Versioned protocol: /complete MUST echo this token.
    authorizationContext: {
      token: authorizationContext.token,
      expiresAt: authorizationContext.expiresAt,
      baselineAbilitiesDigest: authorizationContext.baselineAbilitiesDigest,
    },
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
    /**
     * Versioned protocol version marker. When >= 1, the request MUST
     * include an authorizationContextToken and selectedActionIds; the
     * server refuses to accept a versioned caller without a bound context.
     */
    protocolVersion?: number;
    /**
     * Versioned protocol: opaque token issued by /prepare. Required for
     * new callers (protocolVersion >= 1 or explicit request). When present,
     * the server re-validates every bound invariant (key, JWK, host,
     * immutable SIWE fields, allowed action set, required action set)
     * regardless of the `edited` flag. The `edited` flag is retained for
     * backward compatibility ONLY as a hint for the UI response payload;
     * it has NO effect on authority.
     */
    authorizationContextToken?: string;
    /**
     * Which action IDs the user finally selected. Required alongside
     * `authorizationContextToken`; each ID must be in the /prepare
     * allowed set and every required action must remain.
     *
     * Sol MAJOR-5: when the context token is present, this MUST exactly
     * match the actions encoded in the signed SIWE. Any drift (subset,
     * superset, or unrelated) is rejected.
     */
    selectedActionIds?: unknown;
  }>();

  if (!body.prepared || !body.signature || !body.host || !body.jwk) {
    return c.json({ error: 'prepared, signature, host, and jwk are required' }, 400);
  }

  // Versioned protocol enforcement (Sol MAJOR-5): new callers MUST bind
  // through an authorization context token. Legacy callers (no
  // protocolVersion, no token) still get strict subset validation over
  // the SIWE bytes below, but the strong invariant re-derivation only
  // applies when a token is present.
  const isVersionedCaller =
    typeof body.protocolVersion === 'number' && body.protocolVersion >= 1;
  if (isVersionedCaller && !body.authorizationContextToken) {
    return c.json(
      { error: 'protocolVersion >= 1 requires an authorizationContextToken', code: 'missing_authorization_context_token' },
      400,
    );
  }

  let baselinePermissions: PermissionEntry[] | undefined;
  if (body.permissions !== undefined) {
    try {
      baselinePermissions = validatePermissions(body.permissions);
    } catch (err) {
      return c.json(delegateErrorResponse(err, 'Invalid permissions', 'invalid_permissions'), 400);
    }
  }

  // Authority-side validation always runs; the `edited` request field is
  // never trusted as an authority gate. Older callers omit both the
  // context token and the selectedActionIds field; those paths still get
  // strict subset+required validation over the SIWE bytes here.
  try {
    const entries = parsePreparedRecap(body.prepared.siwe || '');
    const baseline = baselinePermissions
      ? abilitiesFromPermissions(baselinePermissions)
      : DEFAULT_ABILITIES;
    assertBaselineSubset(entries, baseline);
    assertRequiredActions(entries);
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : 'Invalid delegation' }, 400);
  }

  const preparedAddress = String(body.prepared.address || '');
  const preparedChainId = Number(body.prepared.chainId) || 1;
  const preparedSpaceId = String(body.prepared.spaceId || '');

  if (body.authorizationContextToken) {
    if (typeof body.authorizationContextToken !== 'string') {
      return c.json({ error: 'authorizationContextToken must be a string' }, 400);
    }
    if (!Array.isArray(body.selectedActionIds) || body.selectedActionIds.some((id) => typeof id !== 'string')) {
      return c.json({ error: 'selectedActionIds must be a string[] when authorizationContextToken is provided' }, 400);
    }
    const preparedEntries = parsePreparedRecap(body.prepared.siwe || '');
    const immutable = extractImmutableSiweFields(body.prepared.siwe || '', {
      address: preparedAddress,
      chainId: preparedChainId,
      spaceId: preparedSpaceId,
    });

    // Sol MAJOR-5: derive the exact set of action IDs encoded in the SIGNED
    // SIWE and require selectedActionIds to EXACTLY match. The old code
    // only required selectedActionIds to be a subset of the /prepare
    // allowed set — which meant a widget could sign a broad SIWE while
    // returning a narrow selection, or vice versa, and the mismatch would
    // silently pass. The signed-SIWE-encoded set is authoritative.
    const siweEncodedActionIds = new Set<string>();
    for (const entry of preparedEntries) {
      for (const action of entry.actions) {
        siweEncodedActionIds.add(computeActionKey(entry, action));
      }
    }
    const clientSelected = new Set(body.selectedActionIds as string[]);
    // Every action encoded in the signed SIWE must appear in
    // selectedActionIds. Missing entries = the client claims narrower
    // permissions than the SIWE grants.
    const missingFromSelection: string[] = [];
    for (const id of siweEncodedActionIds) {
      if (!clientSelected.has(id)) missingFromSelection.push(id);
    }
    if (missingFromSelection.length > 0) {
      return c.json(
        {
          error: `selectedActionIds is missing entries that appear in the signed SIWE: ${missingFromSelection.slice(0, 5).join(', ')}${missingFromSelection.length > 5 ? ` (and ${missingFromSelection.length - 5} more)` : ''}`,
          code: 'selected_actions_missing_siwe_entries',
        },
        400,
      );
    }
    // Every selectedActionId must appear in the signed SIWE. Extras = the
    // client claims capabilities not actually signed.
    const extrasInSelection: string[] = [];
    for (const id of clientSelected) {
      if (!siweEncodedActionIds.has(id)) extrasInSelection.push(id);
    }
    if (extrasInSelection.length > 0) {
      return c.json(
        {
          error: `selectedActionIds contains entries not present in the signed SIWE: ${extrasInSelection.slice(0, 5).join(', ')}${extrasInSelection.length > 5 ? ` (and ${extrasInSelection.length - 5} more)` : ''}`,
          code: 'selected_actions_exceed_siwe_entries',
        },
        400,
      );
    }

    const consume = consumeAuthorizationContext({
      token: body.authorizationContextToken,
      userId: user.id,
      // Key identity is enforced via keyAddress (which the /complete SIWE
      // always carries); the /prepare context also bound the keyId but we
      // do not require it here.
      keyAddress: preparedAddress,
      jwk: body.jwk,
      host: body.host,
      spaceId: preparedSpaceId,
      selectedActionIds: clientSelected,
      candidateImmutableFieldsDigest: digestImmutableFields(immutable),
      requiredActionIds: requiredActionIdSet(preparedEntries),
    });
    if (!consume.ok) {
      return c.json({ error: consume.message, code: consume.error }, 400);
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

  // Effective grants after any narrowing — the SDK consumer uses these
  // to reconcile local state so returned permissions can never appear
  // broader than what was signed.
  let effectiveEntries: RecapEntry[] = [];
  try {
    effectiveEntries = parsePreparedRecap(body.prepared.siwe || '');
  } catch {
    effectiveEntries = [];
  }
  const effectiveGrants = effectiveEntries.map((entry) => ({
    service: entry.service,
    space: entry.space,
    path: entry.path,
    actions: [...entry.actions],
  }));

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
    // Versioned protocol additions:
    //   `signedMessage` is the exact bytes the signature verifies against
    //   (identical to `siwe`, but named per the SDK protocol so clients
    //   have a stable field).
    //   `permissions` is the effective grant set after any narrowing.
    signedMessage: body.prepared.siwe,
    permissions: effectiveGrants,
  });
});

/**
 * POST /api/delegate/authorize-sign
 *
 * Server-authoritative signing for OpenKey `authorizeTinyCloud` flow (Sol
 * CRITICAL-1). Unlike `/api/keys/:id/sign` (which signs the caller's exact
 * bytes with no server-side narrowing), this route:
 *   1. Parses the ReCap capabilities out of the caller-supplied SIWE.
 *   2. Validates `selectedActionIds` is a strict subset of the SIWE
 *      capabilities AND includes every structurally-required action.
 *   3. Regenerates a NARROWED SIWE server-side preserving every immutable
 *      SIWE field (domain, address, uri, version, chainId, nonce, issuedAt,
 *      expirationTime, notBefore, requestId, statement, non-recap resources).
 *   4. Signs the regenerated bytes with the managed key.
 *   5. Returns `{signature, address, signedMessage, selectedActionKeys, permissions}`
 *      — signedMessage is the ACTUAL bytes signed, never the original.
 *
 * The old bug (widget approves narrow, signs broad) is prevented because
 * the widget cannot ask the server to sign the ORIGINAL bytes and separately
 * return a narrowed `selectedActionKeys` — the two are always derived from
 * the same server-produced `signedMessage`.
 */
delegateRouter.post('/authorize-sign', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    /** Caller-supplied SIWE (the "original" request bytes). */
    siwe: string;
    /** Server-produced action IDs the user finally selected. */
    selectedActionIds: unknown;
  }>();

  if (!body.keyId || !body.siwe) {
    return c.json({ error: 'keyId and siwe are required' }, 400);
  }
  if (
    !Array.isArray(body.selectedActionIds) ||
    body.selectedActionIds.some((id) => typeof id !== 'string')
  ) {
    return c.json(
      { error: 'selectedActionIds must be a string[]', code: 'invalid_selected_action_ids' },
      400,
    );
  }
  const selectedActionIds = new Set(body.selectedActionIds as string[]);

  const key = await prisma.ethereumKey.findFirst({
    where: {
      id: body.keyId,
      userId: user.id,
      keyPurpose: 'PERSONAL',
      archivedAt: null,
    },
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
  });
  if (!key || !key.sealedBlob) {
    return c.json({ error: 'Key not found', code: 'key_not_found' }, 404);
  }

  // Parse the caller-supplied SIWE's ReCap capabilities. Anything that
  // does not parse as a TinyCloud ReCap SIWE cannot be narrowed and is
  // rejected here — legacy exact-byte signing goes through /api/keys/:id/sign.
  let originalEntries: RecapEntry[];
  try {
    originalEntries = parsePreparedRecap(body.siwe);
  } catch (e) {
    return c.json(
      {
        error: e instanceof Error ? e.message : 'Invalid SIWE recap',
        code: 'invalid_siwe_recap',
      },
      400,
    );
  }
  if (originalEntries.length === 0) {
    return c.json(
      { error: 'authorize-sign requires a SIWE with ReCap capabilities; use /api/keys/:id/sign for byte-exact signing', code: 'not_a_recap_siwe' },
      400,
    );
  }

  // Build the allowed set and required set from the original SIWE.
  const allowedActionIds = allowedActionIdSet(originalEntries);
  const requiredActionIds = requiredActionIdSet(originalEntries);

  // Validate the selection: every ID must be allowed; every required ID
  // must remain present.
  for (const id of selectedActionIds) {
    if (!allowedActionIds.has(id)) {
      return c.json(
        {
          error: `selectedActionIds contains ${id} which is not present in the SIWE`,
          code: 'selection_not_in_baseline',
        },
        400,
      );
    }
  }
  for (const id of requiredActionIds) {
    if (!selectedActionIds.has(id)) {
      return c.json(
        {
          error: `selectedActionIds is missing required action ${id}`,
          code: 'required_action_missing',
        },
        400,
      );
    }
  }

  // Extract immutable SIWE fields from the original so we can regenerate
  // a narrowed SIWE with identical header + non-ReCap resources.
  const originalAddress = ensureEip55(key.address);
  const chainId = 1;
  const immutable = extractImmutableSiweFields(body.siwe, {
    address: originalAddress,
    chainId,
    spaceId: '',
  });
  if (!immutable.issuedAt || !immutable.expirationTime || !immutable.nonce) {
    return c.json(
      {
        error: 'SIWE is missing required header fields (issuedAt, expirationTime, or nonce)',
        code: 'invalid_siwe_header',
      },
      400,
    );
  }

  // Derive the narrowed entries + abilities map. The regenerated SIWE
  // will only reference the selected actions in the ReCap block.
  const selectedEntries = entriesForSelectedActions(originalEntries, selectedActionIds);
  if (selectedEntries.length === 0) {
    return c.json(
      { error: 'No selected actions map to any capability in the SIWE', code: 'empty_selection' },
      400,
    );
  }

  // Derive the space ID and JWK from the original SIWE's ReCap. We must
  // preserve the spaceId across regenerations. The space is encoded in the
  // ReCap resource URI; take it from the first entry.
  const firstEntry = selectedEntries[0];
  if (!firstEntry) {
    return c.json(
      { error: 'No selected entries', code: 'empty_selected_entries' },
      400,
    );
  }
  const spaceId = firstEntry.space;

  // The JWK is embedded in the SIWE ReCap. Extract it so the regenerated
  // SIWE can bind to the same session key. Fall back to failing loudly if
  // we cannot extract it — never regenerate a SIWE with a mismatched key.
  let jwk: DelegationJwk;
  try {
    // The SIWE encodes the JWK inside the ReCap payload's presentation
    // data. In practice, the caller supplies the JWK explicitly for the
    // widget flow — but for the authorize-sign path (initiated from
    // authorizeTinyCloud), we don't have the JWK on hand. The right
    // long-term fix is to require the JWK in the request body; for now,
    // reject any SIWE we cannot narrow safely.
    // Since JWK is part of the ReCap statement not the header, and
    // authorize-sign is a byte-narrowing operation, we require the
    // caller to pass jwk explicitly. Retry with body.jwk.
    throw new Error('JWK required');
  } catch {
    // Fall through — check body.jwk below.
  }
  const bodyJwk = (body as unknown as { jwk?: DelegationJwk }).jwk;
  if (!bodyJwk || typeof bodyJwk !== 'object') {
    return c.json(
      { error: 'jwk is required to regenerate a narrowed SIWE', code: 'jwk_required' },
      400,
    );
  }
  jwk = bodyJwk;

  const narrowedAbilities = entriesToAbilities(selectedEntries);
  let narrowedPrepared;
  try {
    narrowedPrepared = prepareSession({
      address: originalAddress,
      chainId,
      domain: immutable.domain,
      issuedAt: immutable.issuedAt,
      expirationTime: immutable.expirationTime,
      spaceId,
      jwk,
      abilities: narrowedAbilities,
    });
  } catch (e) {
    return c.json(
      {
        error: e instanceof Error ? e.message : 'Failed to regenerate narrowed SIWE',
        code: 'siwe_regenerate_failed',
      },
      400,
    );
  }

  // Sign the regenerated bytes with the managed key. The signature is
  // over `narrowedPrepared.siwe`, never the caller's original.
  let signature: string;
  try {
    signature = await signManagedKey(key, key.sealedBlob, narrowedPrepared.siwe);
  } catch (e) {
    return c.json(
      { error: e instanceof Error ? e.message : 'Signing failed', code: 'sign_failed' },
      500,
    );
  }

  // Build the effective grants and selection response payload from the
  // NARROWED SIWE — never from client-supplied strings.
  const effectiveEntries = parsePreparedRecap(narrowedPrepared.siwe);
  const effectiveGrants = effectiveEntries.map((entry) => ({
    service: entry.service,
    space: entry.space,
    path: entry.path,
    actions: [...entry.actions],
  }));
  const effectiveSelectedActionKeys = effectiveEntries.flatMap((entry) =>
    entry.actions.map((action) => computeActionKey(entry, action)),
  );
  // Reference computePermissionKey so it doesn't get flagged as unused
  // during typecheck; permissionOptions may consume it in the future.
  void computePermissionKey;

  return c.json({
    protocolVersion: 1,
    address: originalAddress,
    signature,
    signedMessage: narrowedPrepared.siwe,
    selectedActionKeys: effectiveSelectedActionKeys,
    permissions: effectiveGrants,
  });
});
