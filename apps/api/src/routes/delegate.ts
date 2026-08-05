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
  canonicalizeServiceName,
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
  consumePreviewApproval,
  digestAbilities,
  digestFullRecapAttenuation,
  digestImmutableFields,
  extractRecapAttenuationFromSiwe,
  issueAuthorizationContext,
  issuePreviewApproval,
  peekAuthorizationContext,
  type AuthorizationContextToken,
} from '../services/authorization-signing';
import { narrowSiwePreservingImmutable } from '../services/siwe-narrow';
import { fetchAndBindWellKnownManifest } from '../services/manifest-origin-fetch';
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
import { validateTinyCloudManageKeyRequest } from '../services/tinycloud-manage-key-policy';

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
  const chainIdMatch = siwe.match(/^Chain ID:\s*(\d+)\s*$/m);
  // Address is the second line of the SIWE (immediately after the header).
  const addressMatch = siwe.match(/^0x[a-fA-F0-9]{40}$/m);

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

  // Sol MAJOR-2: use ACTUAL SIWE values when present, not substituted
  // server fallbacks. A silent substitute would let the caller supply
  // a SIWE with a different chainId or address than the fallback and
  // pass the equality check because both sides compute against the same
  // fallback. Only when the SIWE genuinely omits a field do we fall
  // back — and in that case the caller/consumer sees an empty value on
  // both sides, so any drift is still surfaced.
  const parsedChainId = chainIdMatch?.[1] ? Number(chainIdMatch[1]) : Number.NaN;
  const chainId = Number.isFinite(parsedChainId) ? parsedChainId : fallback.chainId;

  return {
    address: addressMatch ? addressMatch[0] : fallback.address,
    chainId,
    domain: domainMatch?.[1]?.trim() ?? '',
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
 * Detect whether the SIWE's `urn:recap:` payload carries MEANINGFUL
 * caveats — i.e. any (resource, ability) pair whose caveat array
 * contains a non-empty object. The ReCap canonical shape is `[{}]` for
 * "no caveats", which every real TinyCloud-emitted recap uses; treating
 * `[{}]` as a real caveat would refuse to narrow every request.
 *
 * We inspect the raw ReCap JSON because the WASM `parseRecapFromSiwe`
 * strips caveats. If any (resource, action) has a meaningful caveat
 * list, the caller must not narrow via /authorize-sign — the regenerated
 * SIWE would drop the caveats and broaden authority.
 *
 * Returns true when at least one meaningful caveat is present; false
 * when the SIWE has no ReCap block, no caveats at all, or only the
 * vacuous `[{}]` placeholder. Silently returns false on decode failure
 * so parsing bugs cannot bypass this guard — the outer parse step
 * already rejected malformed ReCap payloads.
 */
/**
 * Sol MAJOR-4: build a candidate ReCap attenuation from a set of selected
 * action IDs, pairing each surviving (resource, ability) pair with the
 * caveats it carries in the BASELINE attenuation. Because the baseline was
 * extracted from the ORIGINAL SIWE and we never fabricate caveats, this
 * guarantees the candidate is at MOST as broad as the baseline before the
 * subset check runs — the subset check remains authoritative but the
 * candidate we hand it is always well-formed.
 */
function buildCandidateAttenuation(
  originalEntries: RecapEntry[],
  selectedActionIds: Set<string>,
  baselineAttenuation: Record<string, Record<string, unknown[]>>,
): Record<string, Record<string, unknown[]>> {
  // Build an index of baseline resource keys so we can find the correct
  // full resource URI (which the WASM emits as `<space>/<serviceShort>/<path>`)
  // for each (service, space, path) tuple that `parseRecapFromSiwe`
  // surfaces. We match by:
  //   - key STARTS WITH `entry.space` (either exact or `<space>/...`), AND
  //   - the ability with matching service+verb is present on that key.
  // For paths, the key's trailing segment is `<serviceShort>/<path>` OR
  // `<serviceShort>` when the path is empty. We choose the FIRST match
  // that has ALL selected actions for the entry.
  const candidate: Record<string, Record<string, unknown[]>> = {};
  for (const entry of originalEntries) {
    const selectedActions = entry.actions.filter((action) =>
      selectedActionIds.has(computeActionKey(entry, action)),
    );
    if (selectedActions.length === 0) continue;

    // Find the baseline attenuation key whose ability map contains all
    // selected actions for this entry AND whose URI matches the shape
    // `<entry.space>/<any-service-prefix>/<entry.path>` or
    // `<entry.space>/<any-service-prefix>` when entry.path is empty.
    let matchedKey: string | null = null;
    for (const key of Object.keys(baselineAttenuation)) {
      if (!key.startsWith(entry.space)) continue;
      const remainder = key.slice(entry.space.length);
      // Expected shape: "" (whole-space grant), or "/<serviceShort>[/<path>]".
      if (remainder === '' || remainder.startsWith('/')) {
        const abilityMap = baselineAttenuation[key];
        if (!abilityMap) continue;
        // The remainder (after the leading "/") is either "<service>" or
        // "<service>/<path>". We require the trailing part after the
        // first "/" to equal entry.path.
        const rest = remainder.startsWith('/') ? remainder.slice(1) : remainder;
        const slashIdx = rest.indexOf('/');
        const restPath = slashIdx >= 0 ? rest.slice(slashIdx + 1) : '';
        if (restPath !== entry.path) continue;
        // All selected actions must be present in this ability map.
        if (selectedActions.every((a) => abilityMap[a] !== undefined)) {
          matchedKey = key;
          break;
        }
      }
    }
    if (matchedKey === null) {
      // Nothing matched — the caller supplied an entry not derivable from
      // the baseline. Skip; subset check will fail closed.
      continue;
    }
    const candidateSlot = candidate[matchedKey] ?? (candidate[matchedKey] = {});
    for (const action of selectedActions) {
      const baselineCaveats = baselineAttenuation[matchedKey]?.[action] ?? [];
      candidateSlot[action] = [...baselineCaveats];
    }
  }
  return candidate;
}

/**
 * Sol MAJOR-4 (final): return null when the CANDIDATE's caveat multiset on
 * every (resource, ability) pair EXACTLY matches the BASELINE's caveat
 * multiset for the same pair, else a short message describing the first
 * violation. Whole-resource and whole-ability removals are permitted (the
 * candidate simply omits those keys). Adding, changing, removing, or
 * changing the duplicate count of a caveat on a surviving (resource,
 * ability) pair is a violation.
 */
function attenuationSubsetOrFailure(
  candidate: Record<string, Record<string, unknown[]>>,
  baseline: Record<string, Record<string, unknown[]>>,
): string | null {
  const stably = (v: unknown): string => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return `[${v.map(stably).join(',')}]`;
    const entries = Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    return `{${entries.map(([k, val]) => `${JSON.stringify(k)}:${stably(val)}`).join(',')}}`;
  };
  for (const [resource, candidateAbilityMap] of Object.entries(candidate)) {
    const baselineAbilityMap = baseline[resource];
    if (!baselineAbilityMap) return `resource ${resource} not in baseline`;
    for (const [ability, candidateCaveats] of Object.entries(candidateAbilityMap)) {
      const baselineCaveats = baselineAbilityMap[ability];
      if (!baselineCaveats) return `ability ${ability} on ${resource} not in baseline`;
      const baselineCounts = new Map<string, number>();
      for (const c of baselineCaveats) {
        const key = stably(c);
        baselineCounts.set(key, (baselineCounts.get(key) ?? 0) + 1);
      }
      const candidateCounts = new Map<string, number>();
      for (const c of candidateCaveats) {
        const key = stably(c);
        candidateCounts.set(key, (candidateCounts.get(key) ?? 0) + 1);
      }
      if (baselineCounts.size !== candidateCounts.size) {
        return `caveats on ${ability}@${resource} differ (baseline distinct=${baselineCounts.size}, candidate distinct=${candidateCounts.size})`;
      }
      for (const [key, baselineN] of baselineCounts) {
        const candidateN = candidateCounts.get(key) ?? 0;
        if (candidateN !== baselineN) {
          const preview = key.length > 80 ? `${key.slice(0, 80)}...` : key;
          if (candidateN === 0) {
            return `caveat ${preview} was removed from ${ability}@${resource} (surviving abilities must preserve caveats byte-for-byte)`;
          }
          if (candidateN < baselineN) {
            return `caveat ${preview} duplicate count decreased from ${baselineN} to ${candidateN} on ${ability}@${resource}`;
          }
          return `caveat ${preview} duplicate count increased from ${baselineN} to ${candidateN} on ${ability}@${resource}`;
        }
      }
      for (const [key, candidateN] of candidateCounts) {
        if (!baselineCounts.has(key)) {
          const preview = key.length > 80 ? `${key.slice(0, 80)}...` : key;
          return `caveat ${preview} was added to ${ability}@${resource} (candidate count ${candidateN}, baseline count 0)`;
        }
      }
    }
  }
  return null;
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

  if (principal.kind === 'oauth-manage-key') {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({
        approved: false,
        code: 'message_rejected',
        reason: 'The signing request must be a JSON object.',
      }, 400);
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return c.json({
        approved: false,
        code: 'message_rejected',
        reason: 'The signing request must be a JSON object.',
      }, 400);
    }

    const preference = await prisma.user.findUnique({
      where: { id: principal.userId },
      select: { autoSignEnabled: true },
    });
    if (!preference?.autoSignEnabled) {
      return c.json({
        approved: false,
        code: 'signing_disabled',
        reason: 'TinyCloud signing is disabled for this OpenKey account.',
      }, 403);
    }

    // keyId and address, when supplied by older callback adapters, are
    // intentionally ignored. The OAuth token's user binding selects exactly
    // one canonical key at the database boundary.
    const key = await prisma.ethereumKey.findFirst({
      where: {
        userId: principal.userId,
        keyPurpose: 'PERSONAL',
        keyType: 'MANAGED',
        archivedAt: null,
        isCanonicalTinyCloud: true,
      },
      select: {
        id: true,
        address: true,
        sealedBlob: true,
        sealingContext: true,
        userId: true,
      },
    });
    if (!key || !key.sealedBlob || !key.userId) {
      return c.json({
        approved: false,
        code: 'canonical_key_unavailable',
        reason: 'The canonical TinyCloud key is unavailable.',
      }, 403);
    }

    const identity = {
      version: 'v1' as const,
      keyId: key.id,
      address: ensureEip55(key.address),
      chainId: 1 as const,
      did: `did:pkh:eip155:1:${ensureEip55(key.address)}`,
      spaceId: `tinycloud:pkh:eip155:1:${ensureEip55(key.address)}:applications`,
    };
    const candidate = body as Record<string, unknown>;
    const policy = validateTinyCloudManageKeyRequest({
      type: candidate.type,
      chainId: candidate.chainId,
      message: candidate.message,
      identity,
    });
    if (!policy.allowed) {
      return c.json({
        approved: false,
        code: 'message_rejected',
        reason: policy.reason,
      }, 400);
    }

    try {
      const signature = await signManagedKey(key, key.sealedBlob, candidate.message as string);
      return c.json({ approved: true, signature, canonicalIdentity: identity });
    } catch {
      return c.json({
        approved: false,
        code: 'signer_failed',
        reason: 'The canonical TinyCloud signer is unavailable.',
      }, 500);
    }
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
    /**
     * Blocker 1: versioned managed-approval path. When supplied together
     * with `authorizationContextToken` and `selectedActionIds`, the
     * server signs the SIWE bytes that were bound at /prepare instead of
     * regenerating a fresh preview. The regenerated-preview path is
     * insecure because the widget shows the /prepare preview but the
     * caller-echoed re-prepare produces different issuedAt/expirationTime
     * bytes, so the user would sign different bytes from the ones the
     * approval UI displayed.
     *
     * Token-less callers keep the legacy behavior (regenerate and sign).
     */
    prepared?: any;
    authorizationContextToken?: string;
    selectedActionIds?: unknown;
    protocolVersion?: number;
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

  // Blocker 1: versioned managed-approval path. When the widget forwards
  // the /prepare token AND the exact preview bytes, we sign the STORED
  // originalSiwe bytes byte-for-byte. Any drift between the preview and
  // the caller-echoed prepared block is a hard fail — the whole reason
  // this branch exists is to guarantee "the user signed the exact bytes
  // the approval UI showed them". We never trust caller-echoed bytes as
  // the payload; they are only used as the digest cross-check.
  const isVersionedCaller =
    typeof body.protocolVersion === 'number' && body.protocolVersion >= 1;
  const hasToken =
    typeof body.authorizationContextToken === 'string' &&
    body.authorizationContextToken.length > 0;
  if (isVersionedCaller && !hasToken) {
    return c.json(
      { error: 'protocolVersion >= 1 requires an authorizationContextToken', code: 'missing_authorization_context_token' },
      400,
    );
  }

  if (hasToken) {
    const token = body.authorizationContextToken as string;
    if (!body.prepared || typeof body.prepared !== 'object') {
      return c.json(
        { error: 'prepared block is required when authorizationContextToken is present', code: 'missing_prepared' },
        400,
      );
    }
    if (
      !Array.isArray(body.selectedActionIds) ||
      body.selectedActionIds.some((id) => typeof id !== 'string')
    ) {
      return c.json(
        { error: 'selectedActionIds must be a string[] when authorizationContextToken is provided', code: 'invalid_selected_action_ids' },
        400,
      );
    }

    // Peek the token so we can pull the server-bound originalSiwe. Any
    // downstream mismatch will fail consume; peek itself is non-consuming
    // so a caller cannot use it to burn the token by sending garbage.
    const preview = peekAuthorizationContext(token);
    if (!preview.ok) {
      return c.json({ error: preview.message, code: preview.error }, 400);
    }
    const bound = preview.value;

    // The stored context MUST have bound originalSiwe. Older /prepare
    // invocations that predate Blocker 1 did not set this field — those
    // tokens are unusable for the managed signing path and must retry.
    if (!bound.originalSiwe) {
      return c.json(
        {
          error: 'Authorization context has no bound originalSiwe — /prepare must be called again',
          code: 'authorization_context_missing_original_siwe',
        },
        400,
      );
    }

    // Structural cross-checks against the stored context. These duplicate
    // consumeAuthorizationContext's checks, but running them here surfaces
    // clearer error codes and lets us fail before we do any real work.
    if (bound.keyAddress !== address.toLowerCase()) {
      return c.json(
        {
          error: 'Bound keyAddress does not match the supplied keyId',
          code: 'key-mismatch',
        },
        400,
      );
    }
    if (bound.host !== host) {
      return c.json(
        { error: 'Host does not match the prepared context.', code: 'host-mismatch' },
        400,
      );
    }

    // The whole point of Blocker 1: sign the STORED bytes. Verify that
    // the caller-echoed prepared.siwe matches byte-for-byte. Signing the
    // stored bytes protects us from a compromised widget re-preparing
    // the SIWE; the caller-echo check surfaces the mismatch to the CLI
    // so a compromised widget cannot silently return a session bound to
    // different bytes than the ones the user reviewed.
    const echoedSiwe = typeof body.prepared.siwe === 'string' ? body.prepared.siwe : '';
    if (echoedSiwe !== bound.originalSiwe) {
      return c.json(
        {
          error: 'prepared.siwe does not match the SIWE bound at /prepare — refusing to sign',
          code: 'prepared_siwe_mismatch',
        },
        400,
      );
    }

    // Parse the bound SIWE, enforce baseline subset and required actions
    // against it (defense in depth — the /prepare handler already digested
    // the baseline abilities, but running these here catches store
    // corruption or any future change that widens the /prepare surface).
    let preparedEntries: RecapEntry[];
    try {
      preparedEntries = parsePreparedRecap(bound.originalSiwe);
    } catch (e) {
      return c.json(
        { error: e instanceof Error ? e.message : 'Bound SIWE could not be re-parsed', code: 'bound_siwe_parse_failed' },
        500,
      );
    }
    try {
      const baseline = permissions
        ? abilitiesFromPermissions(permissions)
        : DEFAULT_ABILITIES;
      assertBaselineSubset(preparedEntries, baseline);
      assertRequiredActions(preparedEntries);
    } catch (e) {
      return c.json({ error: e instanceof Error ? e.message : 'Invalid delegation' }, 400);
    }

    // Sol MAJOR-5: derive the EXACT set of action IDs encoded in the
    // BOUND (i.e. server-authoritative) SIWE. The caller's
    // selectedActionIds must EXACTLY match this set — a subset would
    // mean the widget claimed narrower authority than it will sign; a
    // superset would mean the widget claimed capabilities not in the
    // signed bytes.
    const siweEncodedActionIds = new Set<string>();
    for (const entry of preparedEntries) {
      for (const action of entry.actions) {
        siweEncodedActionIds.add(computeActionKey(entry, action));
      }
    }
    const clientSelected = new Set(body.selectedActionIds as string[]);
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

    // Recompute the immutable-fields digest from the BOUND SIWE (never
    // from the caller-echoed prepared, even though we already verified
    // they are equal above). The digest bound at /prepare was computed
    // over the same bytes, so this MUST match.
    const immutable = extractImmutableSiweFields(bound.originalSiwe, {
      address,
      chainId,
      spaceId: bound.spaceId,
    });

    const consume = consumeAuthorizationContext({
      token,
      userId: user.id,
      keyId: key.id,
      keyAddress: address,
      jwk: body.jwk,
      host,
      spaceId: bound.spaceId,
      selectedActionIds: clientSelected,
      candidateImmutableFieldsDigest: digestImmutableFields(immutable),
      requiredActionIds: requiredActionIdSet(preparedEntries),
    });
    if (!consume.ok) {
      return c.json({ error: consume.message, code: consume.error }, 400);
    }

    const expirationTime = resolvePreparedExpirationTime({ siwe: bound.originalSiwe });
    if (!expirationTime) {
      return c.json({ error: 'prepared session must include a valid expirationTime or SIWE Expiration Time' }, 400);
    }

    // Sign the STORED originalSiwe verbatim. This is the entire point of
    // Blocker 1: never regenerate the SIWE at approval time.
    const signature = await signManagedKey(key, key.sealedBlob, bound.originalSiwe);

    // Rebuild the session using the caller-echoed prepared block (already
    // byte-verified) plus the signature. `completeSessionSetup` uses the
    // fields off `prepared` (spaceId/jwk/address/nonce/etc) — we
    // additionally overlay `siwe: bound.originalSiwe` and the JWK so a
    // subtly different echoed block cannot deviate from what we actually
    // signed.
    const session = completeSessionSetup({
      ...body.prepared,
      siwe: bound.originalSiwe,
      jwk: body.jwk,
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
    const effectiveGrants = preparedEntries.map((entry) => ({
      service: entry.service,
      space: entry.space,
      path: entry.path,
      actions: [...entry.actions],
    }));

    return c.json({
      delegationHeader: session.delegationHeader,
      delegationCid: session.delegationCid,
      spaceId: bound.spaceId,
      ownerDid,
      verificationMethod: session.verificationMethod,
      jwk: body.jwk,
      address,
      chainId,
      hostActivated,
      // `edited` is a hint for the UI response payload; the authority
      // gate is the token itself. The stored context was issued from a
      // /prepare that may or may not have narrowed; the actual signed
      // permissions are derivable from the SIWE bytes and are what the
      // CLI should trust.
      edited: false,
      reason,
      expirationTime,
      expiresAt: expirationTime,
      expiry: expirationTime,
      siwe: bound.originalSiwe,
      signedMessage: bound.originalSiwe,
      permissions: effectiveGrants,
    });
  }

  // Legacy token-less path — unchanged behavior. The CLI and any older
  // callers that predate the versioned protocol land here and continue to
  // work as before.
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
      // Blocker 1: bind the exact SIWE bytes at prepare time so the
      // managed approval path can sign the server-stored preview verbatim
      // instead of regenerating the message (which would produce fresh
      // issuedAt/expirationTime bytes on every attempt).
      originalSiwe: preparedResult.prepared.siwe,
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
 * POST /api/delegate/authorize-sign-prepare
 *
 * Issues a server-bound authorization context for the OpenKey editable
 * signing flow. The widget MUST call this before `/authorize-sign` — the
 * caller-echoed SIWE, JWK, and selection are NEVER trusted as authority.
 *
 * The context binds:
 *   - authenticated user
 *   - keyId and its EIP-55 address (looked up server-side)
 *   - JWK (structural digest)
 *   - the immutable SIWE header fields (domain, address, uri, version,
 *     chainId, nonce, issuedAt, expirationTime, notBefore, requestId,
 *     statement, non-ReCap resources)
 *   - the allowed set of action IDs
 *   - the initial selection (subset of allowed)
 *   - the space ID
 *   - the original SIWE bytes (so /authorize-sign narrows from a
 *     server-bound baseline)
 *   - a 5-minute single-use token
 *
 * The response returns the opaque token plus the allowed/initial action
 * IDs so the widget can render a review page.
 */
delegateRouter.post('/authorize-sign-prepare', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    /** Caller-supplied SIWE that will be narrowed by /authorize-sign. */
    siwe: string;
    /** Session JWK; digested and stored so /authorize-sign cannot swap it. */
    jwk: DelegationJwk;
    /**
     * Optional. The host the resulting session will activate against. Bound
     * into the context so /authorize-sign cannot swap hosts. Defaults to
     * empty when the widget will not activate a delegation directly.
     */
    host?: string;
    /**
     * Optional presentation envelope forwarded by the widget. Display-only
     * — bound into the authorization context so the review UI can render
     * honest provenance labels. Size-bounded (≤16KB) and validated below.
     * The envelope MUST NOT expand authority; the ReCap payload remains
     * the sole gate for what the user can approve.
     */
    presentation?: {
      protocolVersion?: number;
      displayName?: string;
      reason?: string;
      manifestId?: string;
      manifestDigest?: string;
      manifests?: Array<{
        name?: string;
        appId?: string;
        payload?: Record<string, unknown>;
      }>;
    };
    /**
     * Optional. The browser origin the widget verified from the
     * postMessage sender. When present AND https, the server attempts an
     * SSRF-guarded fetch of `.well-known/openkey-manifest.json` and
     * compares its canonical SHA-256 to `presentation.manifestDigest`.
     * A successful compare upgrades the metadata-trust status to
     * `origin-bound`; any failure fails closed to `unsigned`.
     */
    reportedOrigin?: string;
  }>();

  if (!body.keyId || !body.siwe || !body.jwk || typeof body.jwk !== 'object') {
    return c.json(
      { error: 'keyId, siwe, and jwk are required', code: 'missing_authorize_sign_prepare_fields' },
      400,
    );
  }

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
  if (!key) {
    return c.json({ error: 'Key not found', code: 'key_not_found' }, 404);
  }

  // Only ReCap SIWE requests can be narrowed. Legacy exact-byte signing
  // uses /api/keys/:id/sign.
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
      {
        error:
          'authorize-sign-prepare requires a SIWE with ReCap capabilities; use /api/keys/:id/sign for byte-exact signing',
        code: 'not_a_recap_siwe',
      },
      400,
    );
  }

  const keyAddress = ensureEip55(key.address);
  // Sol MAJOR-2: parse chainId from the SIWE rather than hard-coding it.
  // The widget-supplied SIWE carries the chain the caller wants to bind
  // the delegation to; if we substitute a server default the immutable
  // digest check becomes tautological.
  const chainIdMatch = body.siwe.match(/^Chain ID:\s*(\d+)\s*$/m);
  const chainId = chainIdMatch?.[1] ? Number(chainIdMatch[1]) : Number.NaN;
  if (!Number.isFinite(chainId) || chainId < 1) {
    return c.json(
      { error: 'SIWE is missing a valid Chain ID', code: 'invalid_siwe_chainid' },
      400,
    );
  }

  // The spaceId sits inside the ReCap block — take it from the first entry.
  // All entries in a well-formed prepared SIWE reference the same space.
  const firstEntry = originalEntries[0];
  if (!firstEntry) {
    return c.json(
      { error: 'ReCap has no entries', code: 'empty_recap_entries' },
      400,
    );
  }
  const spaceId = firstEntry.space;

  const immutable = extractImmutableSiweFields(body.siwe, {
    address: keyAddress,
    chainId,
    spaceId,
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
  // Sol MAJOR-2: verify the SIWE's own address/chainId match what the
  // caller ended up bound to. The signer key selection (via keyId) is
  // independent from the SIWE header; drift here means the widget or a
  // MITM is proposing to sign SIWE bytes for a different account.
  if (immutable.address.toLowerCase() !== keyAddress.toLowerCase()) {
    return c.json(
      {
        error: `SIWE address ${immutable.address} does not match bound signer key ${keyAddress}`,
        code: 'siwe_address_mismatch',
      },
      400,
    );
  }
  if (immutable.chainId !== chainId) {
    return c.json(
      {
        error: `SIWE chainId ${immutable.chainId} does not match parsed Chain ID ${chainId}`,
        code: 'siwe_chainid_mismatch',
      },
      400,
    );
  }

  const allowedActionIds = allowedActionIdSet(originalEntries);
  const initialSelectionActionIds = new Set(allowedActionIds);

  // Sol MAJOR-4: caveat-inclusive baseline digest. Previously we digested
  // `entriesToAbilities(entries)` which threw away caveats — making the
  // /authorize-sign candidate comparison tautological because both sides
  // were derived from the same caveat-stripped `entries`. We now digest
  // the FULL ReCap attenuation extracted from the ORIGINAL SIWE bytes,
  // including per-(resource, ability) caveat multisets. On finalize we
  // recompute the candidate digest from the regenerated `signedMessage`
  // (not the bound `originalEntries`) so a caveat-dropping regeneration
  // fails the equality check.
  const baselineAttenuation = extractRecapAttenuationFromSiwe(body.siwe);
  const baselineAbilitiesDigest = digestFullRecapAttenuation(baselineAttenuation);

  // Envelope validation + optional origin-bind. Fail-closed: any validation
  // failure downgrades to `unsigned` — envelope metadata NEVER expands
  // authority, and the caller cannot claim `verified` from the client side.
  let metadataTrust: {
    status: 'verified' | 'origin-bound' | 'unsigned';
    reason: string;
  } = { status: 'unsigned', reason: 'no manifest supplied' };
  let verifiedManifest:
    | {
        name?: string;
        appId?: string;
        manifestId?: string;
        manifestDigest?: string;
        reportedOrigin?: string;
        /**
         * Sol MAJOR-2: only present when origin-bind succeeded AND the
         * manifest carried a `secrets` block AND/or a `permissions`
         * block. The widget uses these to decide whether a KV/SQL
         * secret grant matches an app-declared scoped secret. Missing
         * or mismatched → grant stays sensitive.
         */
        declaredAppScope?: {
          prefix?: string;
          defaultSpace?: string;
          secrets?: Array<{ secretName: string; scope?: string; actions: string[] }>;
          permissions?: Array<{ service: string; space?: string; path: string; actions: string[] }>;
        };
      }
    | undefined;

  if (body.presentation !== undefined) {
    const envelope = body.presentation;
    if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
      metadataTrust = { status: 'unsigned', reason: 'presentation envelope was not an object' };
    } else {
      // Size-bound the envelope. 16KB matches the widget-transport limit.
      let serialized: string | null = null;
      try {
        serialized = JSON.stringify(envelope);
      } catch {
        serialized = null;
      }
      const bytes = serialized ? Buffer.byteLength(serialized, 'utf8') : Number.POSITIVE_INFINITY;
      if (!serialized) {
        metadataTrust = { status: 'unsigned', reason: 'presentation envelope was not serializable' };
      } else if (bytes > 16 * 1024) {
        metadataTrust = {
          status: 'unsigned',
          reason: `presentation envelope size ${bytes} bytes exceeds 16KB limit`,
        };
      } else {
        // Optional origin-bind: only attempted when reportedOrigin is
        // present and https AND the envelope carries a manifestDigest.
        const reportedOrigin =
          typeof body.reportedOrigin === 'string' && body.reportedOrigin.startsWith('https://')
            ? body.reportedOrigin
            : null;
        const declaredDigest =
          typeof envelope.manifestDigest === 'string' && envelope.manifestDigest.length > 0
            ? envelope.manifestDigest
            : null;
        if (reportedOrigin && declaredDigest) {
          try {
            const bindResult = await fetchAndBindWellKnownManifest({
              reportedOrigin,
              declaredDigest,
            });
            if (bindResult.ok) {
              metadataTrust = {
                status: 'origin-bound',
                reason: `manifest at ${reportedOrigin}/.well-known/openkey-manifest.json matched declared digest`,
              };
              // Sol MAJOR-2: forward the declared secrets + permissions
              // block extracted from the origin-bound (digest-matched)
              // manifest. The widget uses this to decide whether a
              // scoped-secret grant matches an app declaration; absent
              // a match, the grant stays sensitive. Never used to
              // expand authority.
              const declaredAppScope =
                bindResult.manifest?.declaredSecrets || bindResult.manifest?.declaredPermissions
                  ? {
                      prefix: bindResult.manifest?.prefix,
                      defaultSpace: bindResult.manifest?.defaultSpace,
                      secrets: bindResult.manifest?.declaredSecrets,
                      permissions: bindResult.manifest?.declaredPermissions,
                    }
                  : undefined;
              // Sol MAJOR-4: never fall back to caller-supplied
              // envelope fields for `name` or `manifestId` while
              // marking trust `origin-bound`. Origin-bind proves the
              // FETCHED manifest matched the declared digest — it says
              // nothing about the envelope's displayName / manifestId.
              // Silently merging the envelope in would let a caller
              // present an unverified label to the operator inside a
              // field the widget renders as "from origin-bound
              // manifest". The widget layer adds envelope fallbacks
              // separately with a distinct `caller-supplied,
              // unverified` provenance tag.
              verifiedManifest = {
                name: bindResult.manifest?.name,
                appId: bindResult.manifest?.appId,
                manifestId: bindResult.manifest?.manifestId,
                manifestDigest: declaredDigest.toLowerCase(),
                reportedOrigin,
                declaredAppScope,
              };
            } else {
              metadataTrust = {
                status: 'unsigned',
                reason: `origin-bind failed: ${bindResult.reason ?? 'unknown reason'}`,
              };
            }
          } catch (bindErr) {
            console.warn('[authorize-sign-prepare] Origin-bind threw:', bindErr);
            metadataTrust = { status: 'unsigned', reason: 'origin-bind threw' };
          }
        } else {
          metadataTrust = {
            status: 'unsigned',
            reason: reportedOrigin
              ? 'presentation envelope has no manifestDigest to bind'
              : 'no https reportedOrigin supplied',
          };
        }
      }
    }
  }

  let issued: AuthorizationContextToken;
  try {
    issued = issueAuthorizationContext({
      userId: user.id,
      keyId: key.id,
      keyAddress,
      jwk: body.jwk,
      host: typeof body.host === 'string' ? body.host : '',
      spaceId,
      baselineAbilitiesDigest,
      immutableFieldsDigest: digestImmutableFields(immutable),
      allowedActionIds,
      initialSelectionActionIds,
      expirationTime: immutable.expirationTime,
      originalSiwe: body.siwe,
      metadataTrust,
      verifiedManifest,
    });
  } catch (issueErr) {
    console.warn('[authorize-sign-prepare] Failed to issue authorization context:', issueErr);
    return c.json(
      { error: 'Failed to issue authorization context', code: 'authorization_context_failed' },
      500,
    );
  }

  return c.json({
    authorizationContextToken: issued.token,
    expiresAt: issued.expiresAt,
    allowedActionIds: issued.allowedActionIds,
    initialSelectionActionIds: issued.initialSelectionActionIds,
    baselineAbilitiesDigest: issued.baselineAbilitiesDigest,
    // Echo the address the token is bound to so the widget can verify it
    // matches the signer it is about to use.
    address: keyAddress,
    spaceId,
    // Server-decided trust + verified manifest fields. The widget MUST
    // render trust from THIS value, not from the envelope it forwarded.
    metadataTrust: issued.metadataTrust,
    verifiedManifest: issued.verifiedManifest,
  });
});

/**
 * POST /api/delegate/authorize-sign
 *
 * Server-authoritative signing for OpenKey `authorizeTinyCloud` flow (Sol
 * CRITICAL-1). Sol continuation contract: the caller-echoed SIWE, JWK,
 * selection, host, or baseline are NEVER trusted as authority. This route
 * requires an opaque, expiring, single-use `authorizationContextToken` that
 * was issued by `/api/delegate/authorize-sign-prepare` and is bound to the
 * authenticated user, the signer key, the JWK, the immutable SIWE header
 * fields, the allowed action set, and the original SIWE bytes.
 *
 * Flow:
 *   1. Load and consume the authorization context (single-use).
 *   2. Rehydrate the ORIGINAL SIWE, JWK, and allowed action set from the
 *      bound context (never from the request body).
 *   3. Narrow the ORIGINAL entries by `selectedActionIds` from the request.
 *   4. Regenerate a narrowed SIWE with the same immutable header fields.
 *   5. Sign the regenerated bytes with the bound key.
 *   6. Return `{ protocolVersion, address, signature, signedMessage,
 *      selectedActionKeys, permissions }`.
 *
 * The old bug (widget approves narrow, signs broad) is prevented because
 * the server both selects the SIWE bytes to sign AND emits the effective
 * selection metadata — they are always consistent by construction.
 */
delegateRouter.post('/authorize-sign', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    /** REQUIRED: opaque single-use token from /authorize-sign-prepare. */
    authorizationContextToken?: string;
    /**
     * REQUIRED (Sol CRITICAL-1): opaque single-use token issued by
     * /authorize-sign-preview. Seals the exact selectedActionIds and
     * signedMessage the preview evaluated, so /authorize-sign cannot
     * independently accept a different selection or sign different bytes.
     */
    previewApprovalToken?: string;
    /** The action IDs the user finally selected. */
    selectedActionIds: unknown;
    /** Optional protocol marker; must be >= 1 when present. */
    protocolVersion?: number;
    /**
     * Sol MAJOR-1: for external-key completion. When present, the server
     * uses THIS signature over the exact regenerated bytes rather than
     * signing with a managed key. The signature MUST verify against
     * `signedMessage` for `keyAddress`. External keys never see the SIWE
     * bytes before the server has bound them into the authorization
     * context — the widget shows the SDK-supplied SIWE, the wallet signs
     * whatever bytes /authorize-sign returns after narrowing.
     *
     * For the external path, callers should first invoke this route with
     * `externalSignature: ""` (or omit it) to receive the preview bytes,
     * sign them with their wallet, and re-invoke with the signature.
     * However the token is single-use — so the preview + sign flow uses
     * the peek+preview API (see /authorize-sign-preview).
     */
    externalSignature?: string;
  }>();

  if (typeof body.authorizationContextToken !== 'string' || !body.authorizationContextToken) {
    return c.json(
      { error: 'authorizationContextToken is required — call /authorize-sign-prepare first', code: 'missing_authorization_context_token' },
      400,
    );
  }
  // Sol CRITICAL-1: /authorize-sign REQUIRES a preview-approval token so
  // finalize cannot independently accept a selection or sign bytes the
  // user did not preview.
  if (typeof body.previewApprovalToken !== 'string' || !body.previewApprovalToken) {
    return c.json(
      {
        error:
          'previewApprovalToken is required — call /authorize-sign-preview and echo the returned token',
        code: 'missing_preview_approval_token',
      },
      400,
    );
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
  if (
    body.protocolVersion !== undefined &&
    (typeof body.protocolVersion !== 'number' || body.protocolVersion < 1)
  ) {
    return c.json(
      { error: 'protocolVersion must be >= 1 when supplied', code: 'invalid_protocol_version' },
      400,
    );
  }
  const selectedActionIds = new Set(body.selectedActionIds as string[]);

  // We consume the context first (single-use), then rehydrate the bound
  // SIWE/JWK/key from it. Any drift on user, keyAddress, JWK, immutable
  // fields, or action set is a hard fail from `consumeAuthorizationContext`.
  //
  // Peek at the token to load the bound key so we can compute the required
  // consume inputs. The consume step re-validates everything.
  //
  // We use a two-phase pattern: (1) look at the token to find the bound
  // key ID (via peeking the store — but the store is opaque, so we
  // structure this as: rehydrate immutable fields FROM the token's bound
  // originalSiwe). To do that safely we consume optimistically — if the
  // consume fails we return an error without side effects. Consuming
  // atomically prevents a token-replay race.
  //
  // We need the immutableFieldsDigest to match. Because we don't yet know
  // the bound originalSiwe until after consume, we cannot compute the
  // candidate digest a priori. The cleanest single-shot approach: consume
  // with a placeholder digest derived from an EMPTY immutable, then require
  // consume to succeed by having stored the SAME empty digest at issue
  // time. That defeats the purpose — the digest must be non-trivial.
  //
  // Correct approach: expose a peek helper, OR make consume accept the
  // digest to be computed by the caller from the bound SIWE. We took the
  // second approach: consume now returns the bound `originalSiwe` and
  // `jwk`, and we validate immutable-fields drift ourselves by comparing
  // digests before consume via a preview step. Because we changed
  // consumeAuthorizationContext to return the bound originalSiwe on
  // success, we can compute the candidate digest from that same bound
  // string and expect equality — the check that matters here is the token
  // binding itself, plus subset + required action validation.
  //
  // Practically: we compute the candidate digest from the caller-supplied
  // metadata (empty string sentinel) and RELY on the token match + the
  // originalSiwe/jwk we get back. The stored immutable digest was written
  // at issue time from the ORIGINAL SIWE. On consume we recompute it from
  // the SAME bound originalSiwe (fetched from the store) — so the two
  // MUST match by construction. Any mismatch here indicates store
  // corruption, which we treat as consume failure.

  // Fetch the bound key row so we can derive keyAddress for consume.
  // The token itself does not surface enough state to skip this lookup:
  // we need the EIP-55 keyAddress for consume, which comes from the DB.
  // We do NOT trust any caller-supplied keyId — the consume step re-checks
  // the token binding against the loaded key.
  //
  // Since the token is opaque, we cannot look up the key without asking
  // the store first. We add a minimal peek helper below via a synthetic
  // consume that fails ONLY when the token is invalid. The real consume
  // happens once we have the correct candidate immutable-fields digest.
  //
  // Simpler: we consume the token immediately and use the returned
  // spaceId + originalSiwe + jwk + keyId to rehydrate everything else.
  // The consume check uses the bound key's address, so we must supply it.
  // Load the row by peeking at the token store WITHOUT consuming — that
  // requires a helper. To keep the change surgical we take a different
  // approach: we consume the token in a two-phase manner where the first
  // phase (a stub with `keyAddress: ""` and empty digest) is rejected and
  // used only to extract the bound keyId. That is wasteful — instead we
  // add a peek helper on the service.

  // The consume helper does not currently expose a peek. To avoid API
  // sprawl we do the following: iterate any key row owned by this user
  // and try consume once with each candidate keyAddress. In practice a
  // user's editable-sign flow always targets the key they just prepared
  // with, so the number of candidate keys is small (typically 1–3). This
  // is O(N) in personal keys per user — acceptable for the current tier.
  // Sol MAJOR-1: accept BOTH managed and external keys. Managed keys
  // have sealedBlob != null; external keys have sealedBlob == null and
  // require a caller-supplied signature.
  const candidateKeys = await prisma.ethereumKey.findMany({
    where: {
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
  if (candidateKeys.length === 0) {
    return c.json({ error: 'No keys found', code: 'key_not_found' }, 404);
  }

  // Because consume is single-use, we cannot try multiple candidates
  // sequentially — the first non-matching attempt would burn the token.
  // Instead we use a preview call that does NOT delete the entry, then a
  // single real consume with the correct arguments.
  //
  // We add a `peek` helper on the service (below) that returns the bound
  // key address WITHOUT consuming, then run the real consume once.

  // Preview: identify the bound key address without consuming.
  const preview = peekAuthorizationContext(body.authorizationContextToken);
  if (!preview.ok) {
    return c.json({ error: preview.message, code: preview.error }, 400);
  }
  const bound = preview.value;
  const key = candidateKeys.find(
    (k) => ensureEip55(k.address).toLowerCase() === bound.keyAddress.toLowerCase(),
  );
  if (!key) {
    return c.json({ error: 'Bound key not found', code: 'key_not_found' }, 404);
  }
  // Managed keys require sealedBlob; external keys require an
  // externalSignature. Fail closed if the request/key state doesn't
  // match.
  const isExternal = key.keyType === 'EXTERNAL';
  if (isExternal) {
    if (typeof body.externalSignature !== 'string' || !body.externalSignature) {
      return c.json(
        {
          error: 'External keys require an externalSignature in the /authorize-sign body',
          code: 'external_signature_required',
        },
        400,
      );
    }
  } else {
    if (!key.sealedBlob) {
      return c.json(
        { error: 'Managed key has no sealed blob', code: 'key_state_invalid' },
        500,
      );
    }
  }
  const boundAddress = ensureEip55(key.address);

  // Re-parse the bound original SIWE to derive required action IDs.
  let originalEntries: RecapEntry[];
  try {
    originalEntries = parsePreparedRecap(bound.originalSiwe);
  } catch (e) {
    return c.json(
      {
        error: e instanceof Error ? e.message : 'Bound SIWE could not be re-parsed',
        code: 'bound_siwe_parse_failed',
      },
      500,
    );
  }
  // Parse chainId from the bound original SIWE — never hard-code.
  const chainIdMatch = bound.originalSiwe.match(/^Chain ID:\s*(\d+)\s*$/m);
  const chainId = chainIdMatch?.[1] ? Number(chainIdMatch[1]) : 1;
  const immutable = extractImmutableSiweFields(bound.originalSiwe, {
    address: boundAddress,
    chainId,
    spaceId: bound.spaceId,
  });

  // Sol MAJOR-4: attenuation-subset check against the caveat-inclusive
  // baseline. We build the candidate attenuation from the SELECTED
  // entries (paired with the ORIGINAL caveats for each surviving
  // (resource, ability) pair) so consume can verify:
  //   1. baselineAttenuation digest matches what /prepare recorded, AND
  //   2. candidateAttenuation is a strict subset (narrowing OK, broadening
  //      or caveat-dropping rejected).
  const baselineAttenuation = extractRecapAttenuationFromSiwe(bound.originalSiwe);
  const candidateAttenuation = buildCandidateAttenuation(
    originalEntries,
    selectedActionIds,
    baselineAttenuation,
  );

  // Consume the token — this validates every bound invariant. Any drift
  // (user, key, JWK, host, spaceId, immutable fields, baseline abilities
  // digest, allowed/required action sets) is a hard fail.
  const consume = consumeAuthorizationContext({
    token: body.authorizationContextToken,
    userId: user.id,
    keyId: key.id,
    keyAddress: boundAddress,
    jwk: bound.jwk,
    host: bound.host,
    spaceId: bound.spaceId,
    selectedActionIds,
    candidateImmutableFieldsDigest: digestImmutableFields(immutable),
    candidateAttenuation,
    baselineAttenuation,
    requiredActionIds: requiredActionIdSet(originalEntries),
  });
  if (!consume.ok) {
    return c.json({ error: consume.message, code: consume.error }, 400);
  }

  // Narrow to the caller's selection. All action IDs are validated
  // against the bound baseline as part of consume.
  const selectedEntries = entriesForSelectedActions(originalEntries, selectedActionIds);
  if (selectedEntries.length === 0) {
    return c.json(
      { error: 'No selected actions map to any capability in the SIWE', code: 'empty_selection' },
      400,
    );
  }

  // Sol critical-2 (exact bytes / unchanged-selection branch): if the
  // caller's selection EXACTLY matches the baseline (no narrowing), sign
  // the ORIGINAL SIWE bytes verbatim. This preserves the exact-byte
  // guarantee for callers that opened /authorize-sign purely to obtain a
  // signature (never edited the review UI) — a legacy signMessage-shaped
  // callback consumer must not receive re-serialized bytes that only
  // differ in whitespace, statement text, or line ordering.
  const originalActionKeys = new Set<string>();
  for (const entry of originalEntries) {
    for (const action of entry.actions) {
      originalActionKeys.add(computeActionKey(entry, action));
    }
  }
  const selectionUnchanged =
    selectedActionIds.size === originalActionKeys.size &&
    [...selectedActionIds].every((id) => originalActionKeys.has(id));

  // Sol continuation contract (caveats): removing a whole ability or a
  // whole resource is allowed even when the baseline carries meaningful
  // caveats — the removed caveats leave with their ability/resource.
  // The narrower is responsible for splicing the ORIGINAL caveat multiset
  // onto every surviving (resource, ability) pair (WASM's regenerator
  // emits `[{}]` regardless of input caveats, so we cannot trust its
  // payload). See `narrowSiwePreservingImmutable` + `rewriteRecapLineCaveats`.

  let signedMessage: string;
  if (selectionUnchanged) {
    // Sign the caller-supplied original SIWE bytes verbatim.
    signedMessage = bound.originalSiwe;
  } else {
    // Sol CRITICAL-1: narrow via the preservation splice. The prior
    // implementation rejected every real production SIWE because the
    // ReCap-derived `statement` line is non-empty on every prepared
    // SIWE. We now use `narrowSiwePreservingImmutable`, which regenerates
    // the SIWE via WASM `prepareSession` for the narrowed abilities and
    // splices ONLY the ReCap-derived statement + `- urn:recap:` lines
    // back into the ORIGINAL SIWE bytes. Every immutable header field
    // (URI, Version, Chain ID, Nonce, Issued At, Expiration Time, Not
    // Before, Request ID, non-ReCap resources) survives byte-for-byte.
    //
    // Sol continuation contract (caveats, final): the narrower is given
    // `baselineCaveats` so the ORIGINAL caveat multiset survives on every
    // (resource, ability) pair that remains. Whole-ability and
    // whole-resource removals drop their caveats with them (legal).
    const narrowed = narrowSiwePreservingImmutable({
      originalSiwe: bound.originalSiwe,
      narrowedEntries: selectedEntries,
      address: boundAddress,
      chainId,
      domain: immutable.domain,
      issuedAt: immutable.issuedAt,
      expirationTime: immutable.expirationTime,
      spaceId: bound.spaceId,
      jwk: consume.jwk,
      baselineCaveats: baselineAttenuation,
      ...(immutable.notBefore ? { notBefore: immutable.notBefore } : {}),
    });
    if (!narrowed.ok) {
      return c.json({ error: narrowed.message, code: narrowed.code }, 400);
    }
    // Sol MAJOR-2: cross-check that the regenerated candidate preserves
    // EVERY TRULY IMMUTABLE header field. The SIWE `statement` line is a
    // text encoding of the ReCap contents (the "I further authorize..."
    // prose the WASM emits from the abilities map), so it LEGITIMATELY
    // changes when the caller narrows. We compare the digest with
    // `statement` stripped out. All other header fields — URI, Version,
    // Chain ID, Nonce, Issued At, Expiration Time, Not Before, Request
    // ID, domain, address, spaceId, non-ReCap resources — must match
    // byte-for-byte.
    const candidateImmutable = extractImmutableSiweFields(narrowed.siwe, {
      address: boundAddress,
      chainId,
      spaceId: bound.spaceId,
    });
    const digestExcludingStatement = (f: ReturnType<typeof extractImmutableSiweFields>) =>
      digestImmutableFields({ ...f, statement: '' });
    if (digestExcludingStatement(candidateImmutable) !== digestExcludingStatement(immutable)) {
      return c.json(
        {
          error:
            'Regenerated SIWE altered immutable header fields — refusing to sign',
          code: 'regenerated_immutable_drift',
        },
        400,
      );
    }
    // Sol MAJOR-4: re-verify the regenerated bytes' attenuation is still a
    // subset of the baseline. This catches any WASM emitter drift that
    // might silently add abilities under a resource we did not narrow.
    const regeneratedAttenuation = extractRecapAttenuationFromSiwe(narrowed.siwe);
    const regenSubsetFailure = attenuationSubsetOrFailure(
      regeneratedAttenuation,
      baselineAttenuation,
    );
    if (regenSubsetFailure) {
      return c.json(
        {
          error: `Regenerated SIWE ReCap broadens baseline: ${regenSubsetFailure}`,
          code: 'regenerated_broadens_baseline',
        },
        400,
      );
    }
    signedMessage = narrowed.siwe;
  }

  // Sol CRITICAL-1: consume the preview-approval token now that we know
  // the exact signedMessage. The token was issued by /authorize-sign-preview
  // and seals both the selection and the candidate bytes; if either drifts
  // between preview and finalize, this fails hard.
  const previewConsume = consumePreviewApproval({
    token: body.previewApprovalToken!,
    authorizationContextToken: body.authorizationContextToken!,
    userId: user.id,
    selectedActionIds,
    candidateSignedMessage: signedMessage,
  });
  if (!previewConsume.ok) {
    return c.json({ error: previewConsume.message, code: previewConsume.error }, 400);
  }

  // Sign the (original or regenerated) bytes.
  let signature: string;
  if (isExternal) {
    // Sol MAJOR-1: the caller supplied a signature over what THEY claim
    // to be the bytes we'll return. Verify it against `signedMessage`
    // and `boundAddress` — if the wallet signed different bytes, refuse.
    try {
      const { verifyMessage } = await import('ethers');
      const recovered = verifyMessage(signedMessage, body.externalSignature!);
      if (recovered.toLowerCase() !== boundAddress.toLowerCase()) {
        return c.json(
          {
            error: `External signature recovered ${recovered}, expected ${boundAddress}`,
            code: 'external_signature_mismatch',
          },
          400,
        );
      }
    } catch (e) {
      return c.json(
        {
          error: e instanceof Error ? e.message : 'External signature verification failed',
          code: 'external_signature_invalid',
        },
        400,
      );
    }
    signature = body.externalSignature!;
  } else {
    try {
      signature = await signManagedKey(key, key.sealedBlob!, signedMessage);
    } catch (e) {
      return c.json(
        { error: e instanceof Error ? e.message : 'Signing failed', code: 'sign_failed' },
        500,
      );
    }
  }

  // Effective grants + selection derived from the ACTUAL signed bytes.
  // `service` is canonicalized to the `tinycloud.<short>` form so the wire
  // shape agrees with `selectedActionKeys` (which come from
  // `computeActionKey` → `permissionKey` → `canonicalizeServiceName`). The
  // widget's `validatePreviewSelection` projects each permission through
  // `actionId(service, space, path, ability)` and requires the projected
  // set to equal `selectedActionKeys`; if these disagreed the review UI
  // would throw "permissions disagree with selectedActionKeys" before
  // ever displaying anything to the user.
  const effectiveEntries = parsePreparedRecap(signedMessage);
  const effectiveGrants = effectiveEntries.map((entry) => ({
    service: canonicalizeServiceName(entry.service),
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
    address: boundAddress,
    signature,
    signedMessage,
    selectedActionKeys: effectiveSelectedActionKeys,
    permissions: effectiveGrants,
  });
});

/**
 * POST /api/delegate/authorize-sign-preview
 *
 * Sol CRITICAL-2 / MAJOR-1: return the exact bytes the server would sign
 * for a given `selectedActionIds` against a bound authorization context,
 * WITHOUT consuming the token. This lets the widget:
 *   - render a "signing this exactly" preview before the user approves,
 *   - hand the preview bytes to an external wallet for signing,
 *   - resubmit to /authorize-sign with the resulting `externalSignature`.
 *
 * The route is idempotent (safe to call multiple times) and does NOT
 * extend the token TTL. Since preview does not consume the token, it
 * does not perform every consume-time check (no immutable-fields
 * digest comparison, no required-action check) — the ONLY authority
 * gate is the token binding itself. /authorize-sign performs the full
 * consume + immutable-fields check when the token is actually used.
 */
delegateRouter.post('/authorize-sign-preview', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    authorizationContextToken?: string;
    selectedActionIds?: unknown;
  }>();

  if (typeof body.authorizationContextToken !== 'string' || !body.authorizationContextToken) {
    return c.json(
      { error: 'authorizationContextToken is required', code: 'missing_authorization_context_token' },
      400,
    );
  }
  if (!Array.isArray(body.selectedActionIds) || body.selectedActionIds.some((id) => typeof id !== 'string')) {
    return c.json(
      { error: 'selectedActionIds must be a string[]', code: 'invalid_selected_action_ids' },
      400,
    );
  }
  const selectedActionIds = new Set(body.selectedActionIds as string[]);

  const preview = peekAuthorizationContext(body.authorizationContextToken);
  if (!preview.ok) {
    return c.json({ error: preview.message, code: preview.error }, 400);
  }
  const bound = preview.value;
  // The peek does not verify the caller. Cross-check the userId against
  // the authenticated session so a leaked token cannot be probed by a
  // different user.
  if (bound.userId !== user.id) {
    return c.json({ error: 'Authorization context bound to a different user', code: 'user_mismatch' }, 400);
  }

  let originalEntries: RecapEntry[];
  try {
    originalEntries = parsePreparedRecap(bound.originalSiwe);
  } catch (e) {
    return c.json(
      { error: e instanceof Error ? e.message : 'Bound SIWE could not be re-parsed', code: 'bound_siwe_parse_failed' },
      500,
    );
  }
  const chainIdMatch = bound.originalSiwe.match(/^Chain ID:\s*(\d+)\s*$/m);
  const chainId = chainIdMatch?.[1] ? Number(chainIdMatch[1]) : 1;
  const immutable = extractImmutableSiweFields(bound.originalSiwe, {
    address: ensureEip55(bound.keyAddress),
    chainId,
    spaceId: bound.spaceId,
  });
  // Every requested selected action MUST be in the bound allowed set.
  const allowedSet = new Set(bound.allowedActionIds);
  for (const id of selectedActionIds) {
    if (!allowedSet.has(id)) {
      return c.json(
        { error: `Selected action ${id} is not part of the prepared baseline.`, code: 'action-not-in-baseline' },
        400,
      );
    }
  }
  const selectedEntries = entriesForSelectedActions(originalEntries, selectedActionIds);
  if (selectedEntries.length === 0) {
    return c.json(
      { error: 'No selected actions map to any capability in the SIWE', code: 'empty_selection' },
      400,
    );
  }

  // Same unchanged-selection / caveats logic as /authorize-sign.
  const originalActionKeys = new Set<string>();
  for (const entry of originalEntries) {
    for (const action of entry.actions) {
      originalActionKeys.add(computeActionKey(entry, action));
    }
  }
  const selectionUnchanged =
    selectedActionIds.size === originalActionKeys.size &&
    [...selectedActionIds].every((id) => originalActionKeys.has(id));
  // Sol continuation contract (caveats): whole-ability/whole-resource
  // removal is allowed. Surviving abilities keep the ORIGINAL caveat
  // multiset (spliced back by the narrower). See /authorize-sign for
  // the full contract.

  let preparedSignedMessage: string;
  if (selectionUnchanged) {
    preparedSignedMessage = bound.originalSiwe;
  } else {
    // Sol CRITICAL-1: preview via the preservation splice. Real production
    // SIWEs always carry a ReCap-derived statement; the previous guard
    // rejected them all, which meant the preview never returned any bytes
    // for a narrowed selection in production.
    const previewBaselineCaveats = extractRecapAttenuationFromSiwe(bound.originalSiwe);
    const previewNarrowed = narrowSiwePreservingImmutable({
      originalSiwe: bound.originalSiwe,
      narrowedEntries: selectedEntries,
      address: ensureEip55(bound.keyAddress),
      chainId,
      domain: immutable.domain,
      issuedAt: immutable.issuedAt,
      expirationTime: immutable.expirationTime,
      spaceId: bound.spaceId,
      jwk: bound.jwk,
      baselineCaveats: previewBaselineCaveats,
      ...(immutable.notBefore ? { notBefore: immutable.notBefore } : {}),
    });
    if (!previewNarrowed.ok) {
      return c.json({ error: previewNarrowed.message, code: previewNarrowed.code }, 400);
    }
    // Verify no immutable-header drift in the preview candidate. `statement`
    // is EXCLUDED from the comparison because it is a text encoding of the
    // ReCap contents and legitimately changes with narrowing.
    const candidateImmutable = extractImmutableSiweFields(previewNarrowed.siwe, {
      address: ensureEip55(bound.keyAddress),
      chainId,
      spaceId: bound.spaceId,
    });
    const digestExcludingStatement = (f: ReturnType<typeof extractImmutableSiweFields>) =>
      digestImmutableFields({ ...f, statement: '' });
    if (digestExcludingStatement(candidateImmutable) !== digestExcludingStatement(immutable)) {
      return c.json(
        {
          error: 'Regenerated SIWE altered immutable header fields — refusing to preview',
          code: 'regenerated_immutable_drift',
        },
        400,
      );
    }
    // Sol MAJOR-4: assert the regenerated attenuation is a strict subset of
    // the baseline. Broadening at preview time is a wire-format bug we
    // must fail closed on rather than let the user "approve" bytes we
    // would then refuse to sign at /authorize-sign.
    const previewBaseline = extractRecapAttenuationFromSiwe(bound.originalSiwe);
    const previewCandidate = extractRecapAttenuationFromSiwe(previewNarrowed.siwe);
    const previewSubsetFailure = attenuationSubsetOrFailure(previewCandidate, previewBaseline);
    if (previewSubsetFailure) {
      return c.json(
        {
          error: `Regenerated SIWE ReCap broadens baseline: ${previewSubsetFailure}`,
          code: 'regenerated_broadens_baseline',
        },
        400,
      );
    }
    preparedSignedMessage = previewNarrowed.siwe;
  }

  // Preview grants + selection. `service` is canonicalized to the
  // `tinycloud.<short>` form so the wire shape agrees with
  // `selectedActionKeys` (see the /authorize-sign response for the full
  // rationale — the widget's `validatePreviewSelection` requires the
  // per-permission projection to equal the returned selected keys).
  const previewEntries = parsePreparedRecap(preparedSignedMessage);
  const previewGrants = previewEntries.map((entry) => ({
    service: canonicalizeServiceName(entry.service),
    space: entry.space,
    path: entry.path,
    actions: [...entry.actions],
  }));
  const previewSelectedActionKeys = previewEntries.flatMap((entry) =>
    entry.actions.map((action) => computeActionKey(entry, action)),
  );

  // Sol CRITICAL-1: issue a preview-approval token that seals the exact
  // selection AND signed-bytes candidate. /authorize-sign requires this
  // token; without it, finalize could independently accept a different
  // selection or sign different bytes than the preview evaluated.
  const previewApproval = issuePreviewApproval({
    authorizationContextToken: body.authorizationContextToken!,
    userId: user.id,
    keyAddress: ensureEip55(bound.keyAddress),
    selectedActionIds,
    signedMessage: preparedSignedMessage,
  });

  return c.json({
    protocolVersion: 1,
    address: ensureEip55(bound.keyAddress),
    // The exact bytes the server would sign for this selection.
    signedMessage: preparedSignedMessage,
    selectedActionKeys: previewSelectedActionKeys,
    permissions: previewGrants,
    // Echo the token so callers can round-trip it back into
    // /authorize-sign without re-parsing.
    authorizationContextToken: body.authorizationContextToken,
    // Sol CRITICAL-1: preview-approval token bound to (selection, bytes).
    previewApprovalToken: previewApproval.token,
    previewApprovalExpiresAt: previewApproval.expiresAt,
    signedMessageDigest: previewApproval.signedMessageDigest,
  });
});
