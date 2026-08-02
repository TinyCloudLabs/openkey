// Authorization signing service.
//
// The /prepare handler issues an opaque single-use context describing the
// bounds within which /complete may sign a SIWE. The context is:
//
//   - bound to the authenticated user
//   - bound to the OpenKey key ID and its EIP-55 address
//   - bound to the JWK (structural equality)
//   - bound to the host
//   - bound to the baseline permission digest (sha256 over normalized
//     baseline abilities)
//   - bound to the immutable SIWE field digest (issuedAt/expirationTime/
//     nonce/domain/chainId/spaceId)
//   - bound to the set of allowed action IDs (the baseline set)
//   - bound to the user's initial selection (may be narrowed at /complete)
//   - bound to a nonce
//   - bound to an issue and expiry timestamp
//
// /complete MUST consume the context (single-use). Any deviation — a
// different key, a different host, an added action, an altered immutable
// field, a broadened selection, a signature that verifies against different
// bytes — is rejected. The `edited` flag in the request body is IGNORED
// for authority decisions; authority checks always run.
//
// The context is not persisted to the database — it lives in an in-process
// map keyed by an opaque token. Restarting the API invalidates outstanding
// prepared contexts; the widget must call /prepare again in that case. This
// is intentional: prepared contexts are short-lived (5 minutes) and their
// invalidation is a valid failure mode.

import { createHash, randomUUID, timingSafeEqual } from "node:crypto";

const CONTEXT_TTL_MS = 5 * 60 * 1000;

/**
 * Sol MAJOR-2: shape of the verified-manifest block the server hands to
 * the widget. Includes the origin-bound `declaredAppScope` when the
 * fetched manifest carried a `secrets` or `permissions` block. The
 * widget uses `declaredAppScope` to distinguish grants the app actually
 * asked for from grants a compromised caller injected — but this data
 * is DISPLAY-ONLY. It never expands authority; the ReCap payload is
 * still the sole gate for what the user may approve.
 */
export interface VerifiedManifestFields {
  name?: string;
  appId?: string;
  manifestId?: string;
  manifestDigest?: string;
  reportedOrigin?: string;
  declaredAppScope?: {
    prefix?: string;
    defaultSpace?: string;
    secrets?: Array<{ secretName: string; scope?: string; actions: string[] }>;
    permissions?: Array<{ service: string; space?: string; path: string; actions: string[] }>;
  };
}

export interface AuthorizationContextIssueInput {
  userId: string;
  keyId: string;
  keyAddress: string;
  jwk: unknown;
  host: string;
  spaceId: string;
  baselineAbilitiesDigest: string;
  immutableFieldsDigest: string;
  /** Set of action IDs the baseline SIWE contains. */
  allowedActionIds: Set<string>;
  /** Set of action IDs the widget initially selected (subset of allowed). */
  initialSelectionActionIds: Set<string>;
  /** ISO-8601 expirationTime from the baseline SIWE. */
  expirationTime: string;
  /**
   * The original SIWE bytes bound to this context. Stored so /authorize-sign
   * can narrow from the server-bound baseline instead of trusting a
   * caller-echoed SIWE.
   */
  originalSiwe?: string;
  /**
   * Server-decided trust for the presentation envelope. Bound at prepare
   * time so the widget cannot upgrade it in a later step. Display-only:
   * never expands authority.
   *   - `verified` — reserved for a future signed-manifest path.
   *   - `origin-bound` — the reported browser origin matched an https
   *     well-known manifest whose canonical SHA-256 matched the
   *     envelope's declared digest.
   *   - `unsigned` — no manifest, or verification failed. Fail-closed.
   */
  metadataTrust?: {
    status: "verified" | "origin-bound" | "unsigned";
    reason: string;
  };
  /**
   * The subset of envelope manifest metadata the server was willing to
   * echo back after validation. Never carries the caller's raw envelope;
   * always the server's derived, size-bounded, sanitized version.
   */
  verifiedManifest?: VerifiedManifestFields;
}

interface StoredContext {
  token: string;
  createdAt: number;
  expiresAt: number;
  userId: string;
  keyId: string;
  keyAddress: string;
  jwkDigest: string;
  jwk: unknown;
  host: string;
  spaceId: string;
  baselineAbilitiesDigest: string;
  immutableFieldsDigest: string;
  allowedActionIds: string[];
  initialSelectionActionIds: string[];
  expirationTime: string;
  originalSiwe: string;
  metadataTrust: {
    status: "verified" | "origin-bound" | "unsigned";
    reason: string;
  };
  verifiedManifest?: VerifiedManifestFields;
}

const store = new Map<string, StoredContext>();

function pruneExpired(now: number) {
  for (const [token, ctx] of store) {
    if (ctx.expiresAt <= now) store.delete(token);
  }
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function digestJwk(jwk: unknown): string {
  return sha256Hex(stableStringify(jwk));
}

export function digestAbilities(abilities: unknown): string {
  return sha256Hex(stableStringify(abilities));
}

/**
 * Sol MAJOR-4: digest the FULL normalized ReCap attenuation, INCLUDING per-
 * (resource, ability) caveat multisets. Used as the baseline for
 * `/authorize-sign-prepare` so a narrowed candidate cannot silently drop
 * caveats (which would broaden authority relative to the recorded baseline).
 *
 * The input is the decoded `att` block of the `urn:recap:...` payload — a map
 * from resource URI to (ability → caveats[]).  Caveats are normalized by
 * stable stringification of each caveat object; the caveat list at each
 * (resource, ability) pair is treated as an ORDERED MULTISET (identical to
 * ReCap wire semantics), so a candidate that removes the second of two
 * identical `{}` caveats will still diverge in the digest.
 *
 * The classifier-visible baseline previously used
 * `digestAbilities(entriesToAbilities(entries))` which threw away caveats
 * entirely. That made the equality check tautological because both sides
 * were computed from the same caveat-stripped `entries`. This function
 * closes that gap and MUST be used for both baseline and candidate digests.
 */
export function digestFullRecapAttenuation(
  attenuation: Record<string, Record<string, unknown[]>>,
): string {
  // Normalize: keys sorted, caveat arrays kept in their original order (a
  // change in caveat order is a real change), each caveat stably serialized.
  const normalized: Record<string, Record<string, string[]>> = {};
  const resourceKeys = Object.keys(attenuation).sort();
  for (const resource of resourceKeys) {
    const abilityMap = attenuation[resource] ?? {};
    const abilityKeys = Object.keys(abilityMap).sort();
    const normalizedAbilityMap: Record<string, string[]> = {};
    for (const ability of abilityKeys) {
      const caveats = abilityMap[ability];
      const list = Array.isArray(caveats) ? caveats : [];
      normalizedAbilityMap[ability] = list.map((c) => stableStringify(c));
    }
    normalized[resource] = normalizedAbilityMap;
  }
  return sha256Hex(stableStringify(normalized));
}

/**
 * Parse the `att` block from every `urn:recap:...` resource line in a SIWE.
 * Returns an empty attenuation when the SIWE carries no ReCap resources.
 * Silently skips resources whose payload is not decodable — the outer
 * caller (`parsePreparedRecap` in the delegate route) already asserts that
 * every `urn:recap:` resource is well-formed before this runs.
 */
export function extractRecapAttenuationFromSiwe(
  siwe: string,
): Record<string, Record<string, unknown[]>> {
  const combined: Record<string, Record<string, unknown[]>> = {};
  const lines = siwe.split(/\r?\n/);
  for (const line of lines) {
    const match = line.match(/urn:recap:([A-Za-z0-9_-]+=*)/);
    if (!match || !match[1]) continue;
    try {
      const normalized = match[1].replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
      const json = Buffer.from(padded, 'base64').toString('utf8');
      const parsed = JSON.parse(json) as { att?: Record<string, Record<string, unknown[]>> };
      const att = parsed?.att;
      if (!att || typeof att !== 'object') continue;
      for (const [resource, abilityMap] of Object.entries(att)) {
        if (!abilityMap || typeof abilityMap !== 'object') continue;
        const target = combined[resource] ?? (combined[resource] = {});
        for (const [ability, caveats] of Object.entries(abilityMap)) {
          if (!Array.isArray(caveats)) continue;
          // If the same (resource, ability) appears in multiple ReCap
          // resources (unusual but legal), we concatenate the caveat
          // lists to keep the multiset semantics.
          target[ability] = [...(target[ability] ?? []), ...caveats];
        }
      }
    } catch {
      continue;
    }
  }
  return combined;
}

export function digestImmutableFields(fields: {
  address: string;
  chainId: number;
  domain: string;
  issuedAt: string;
  expirationTime: string;
  spaceId: string;
  nonce: string;
  // Sol MAJOR-5: extended immutable-field coverage. Older callers omit
  // these (the values default to empty string); newer /prepare invocations
  // supply them and /complete re-verifies them.
  uri?: string;
  version?: string;
  notBefore?: string;
  requestId?: string;
  statement?: string;
  nonRecapResources?: string;
}): string {
  // Normalize missing optional fields to empty strings so a caller that
  // supplies { uri: undefined } digests to the same value as one that omits
  // the key entirely. stableStringify already handles this because it uses
  // JSON.stringify, but forcing the shape makes the wire behaviour explicit.
  const normalized = {
    address: fields.address,
    chainId: fields.chainId,
    domain: fields.domain,
    issuedAt: fields.issuedAt,
    expirationTime: fields.expirationTime,
    spaceId: fields.spaceId,
    nonce: fields.nonce,
    uri: fields.uri ?? '',
    version: fields.version ?? '',
    notBefore: fields.notBefore ?? '',
    requestId: fields.requestId ?? '',
    statement: fields.statement ?? '',
    nonRecapResources: fields.nonRecapResources ?? '',
  };
  return sha256Hex(stableStringify(normalized));
}

export interface AuthorizationContextToken {
  token: string;
  expiresAt: string;
  allowedActionIds: string[];
  initialSelectionActionIds: string[];
  /** Baseline digest so the widget can prove it received the right prepare. */
  baselineAbilitiesDigest: string;
  /**
   * Server-decided trust for the presentation envelope (see
   * `AuthorizationContextIssueInput.metadataTrust`). Returned so the widget
   * can render honest provenance labels; the value is bound into the
   * context and cannot be raised by later steps.
   */
  metadataTrust: {
    status: "verified" | "origin-bound" | "unsigned";
    reason: string;
  };
  /** Verified manifest fields (only present when trust status upgrades). */
  verifiedManifest?: VerifiedManifestFields;
}

export function issueAuthorizationContext(
  input: AuthorizationContextIssueInput,
): AuthorizationContextToken {
  const now = Date.now();
  pruneExpired(now);

  const token = `oks_${randomUUID().replace(/-/g, "")}${randomUUID().replace(/-/g, "")}`;
  const jwkDigest = digestJwk(input.jwk);

  const metadataTrust = input.metadataTrust ?? {
    status: "unsigned" as const,
    reason: "no manifest supplied",
  };

  const stored: StoredContext = {
    token,
    createdAt: now,
    expiresAt: now + CONTEXT_TTL_MS,
    userId: input.userId,
    keyId: input.keyId,
    keyAddress: input.keyAddress.toLowerCase(),
    jwkDigest,
    jwk: input.jwk,
    host: input.host,
    spaceId: input.spaceId,
    baselineAbilitiesDigest: input.baselineAbilitiesDigest,
    immutableFieldsDigest: input.immutableFieldsDigest,
    allowedActionIds: [...input.allowedActionIds].sort(),
    initialSelectionActionIds: [...input.initialSelectionActionIds].sort(),
    expirationTime: input.expirationTime,
    originalSiwe: input.originalSiwe ?? "",
    metadataTrust,
    verifiedManifest: input.verifiedManifest,
  };
  store.set(token, stored);

  return {
    token,
    expiresAt: new Date(stored.expiresAt).toISOString(),
    allowedActionIds: stored.allowedActionIds,
    initialSelectionActionIds: stored.initialSelectionActionIds,
    baselineAbilitiesDigest: stored.baselineAbilitiesDigest,
    metadataTrust: stored.metadataTrust,
    verifiedManifest: stored.verifiedManifest,
  };
}

export type ConsumeError =
  | "context-not-found"
  | "context-expired"
  | "user-mismatch"
  | "key-mismatch"
  | "jwk-mismatch"
  | "host-mismatch"
  | "space-mismatch"
  | "baseline-digest-mismatch"
  | "candidate-broadens-baseline"
  | "immutable-fields-changed"
  | "action-not-in-baseline"
  | "action-not-in-initial-selection"
  | "required-action-missing";

export interface ConsumeInput {
  token: string;
  userId: string;
  /**
   * Optional. When provided, must match the keyId bound at /prepare. When
   * absent, the check is skipped — key identity is still enforced via
   * `keyAddress` (which the /complete SIWE always carries).
   */
  keyId?: string;
  keyAddress: string;
  jwk: unknown;
  host: string;
  spaceId: string;
  selectedActionIds: Set<string>;
  /**
   * Recomputed digest for the immutable SIWE fields of the /complete request.
   * If it does not match the digest bound at /prepare, /complete fails.
   */
  candidateImmutableFieldsDigest: string;
  /**
   * DEPRECATED (kept for backward-compat with existing tests): equality-only
   * digest check. Prefer `candidateAttenuation` which enables a proper
   * subset check including caveats.
   *
   * When BOTH `candidateAbilitiesDigest` and `candidateAttenuation` are
   * supplied, the attenuation subset check takes precedence.
   */
  candidateAbilitiesDigest?: string | null;
  /**
   * Sol MAJOR-4: the FULL ReCap attenuation of the candidate SIWE the caller
   * wants to complete, as returned by `extractRecapAttenuationFromSiwe`.
   * When supplied, consume verifies that the candidate attenuation is a
   * STRICT SUBSET of the baseline attenuation bound at /prepare — narrowing
   * is permitted but broadening (any new resource, ability, or caveat) is
   * rejected. Caveats compare as ordered multisets — removing a caveat is
   * broadening because it removes a narrowing constraint.
   *
   * The baseline attenuation is not stored directly on the context (the
   * digest suffices); instead callers pass the ORIGINAL SIWE attenuation
   * on both sides. Consume is a stateless subset test.
   */
  candidateAttenuation?: Record<string, Record<string, unknown[]>>;
  /**
   * Sol MAJOR-4: the baseline ReCap attenuation, as extracted from the
   * ORIGINAL SIWE bound at /prepare. When supplied alongside
   * `candidateAttenuation`, consume runs a subset check against this
   * baseline. This is the SAME attenuation whose digest is stored on the
   * context, so consume additionally cross-checks
   * `digestFullRecapAttenuation(baselineAttenuation) === stored.baselineAbilitiesDigest`
   * before running the subset test — a mismatch means the caller supplied
   * a different baseline than the one bound at /prepare and consume fails
   * fast rather than accepting a subset check against attacker-controlled
   * baseline data.
   */
  baselineAttenuation?: Record<string, Record<string, unknown[]>>;
  /**
   * Set of action IDs that the classifier says are required. Used to enforce
   * the "required actions remain" invariant.
   */
  requiredActionIds: Set<string>;
}

export interface ConsumeSuccess {
  ok: true;
  allowedActionIds: Set<string>;
  selectedActionIds: Set<string>;
  baselineAbilitiesDigest: string;
  spaceId: string;
  expirationTime: string;
  /**
   * The original SIWE bound at issue time. Empty string when no SIWE was
   * bound (legacy /prepare contexts that only carry a digest).
   */
  originalSiwe: string;
  /**
   * The JWK bound at issue time. Returned so /authorize-sign can regenerate
   * the narrowed SIWE without trusting a caller-echoed JWK.
   */
  jwk: unknown;
  /** The keyId bound at issue time. */
  keyId: string;
  /** The host bound at issue time. */
  host: string;
}

export interface ConsumeFailure {
  ok: false;
  error: ConsumeError;
  message: string;
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return timingSafeEqual(bufA, bufB);
}

/**
 * Sol final continuation contract requirement 3: return null when the
 * candidate ReCap attenuation is a legitimate narrowing of the baseline,
 * otherwise return a short human message describing the first violation.
 *
 * Legitimate narrowing (allowed):
 *   - Removing an entire resource from the candidate.
 *   - Removing an entire ability from the candidate on a surviving resource.
 *
 * Forbidden (any of these is a "broadening"):
 *   - Adding a resource or ability not in baseline.
 *   - Adding a caveat to a surviving ability.
 *   - Removing a caveat from a surviving ability.
 *   - Changing (replacing) a caveat on a surviving ability.
 *   - Changing the duplicate count of any caveat on a surviving ability.
 *
 * Rationale: caveats attenuate authority in a way ReCap does not surface
 * a signed proof for; a widget that quietly drops a restrictive caveat
 * would broaden authority relative to the recorded baseline. We therefore
 * require EXACT multiset equality of caveats for every SURVIVING (resource,
 * ability) pair, and allow only whole-ability or whole-resource removal.
 * This matches the js-sdk consumer's `unauthorizedRecapCapabilities`
 * semantics so both sides reject the same set of transformations.
 */
function attenuationSubsetFailure(
  candidate: Record<string, Record<string, unknown[]>>,
  baseline: Record<string, Record<string, unknown[]>>,
): string | null {
  for (const [resource, candidateAbilityMap] of Object.entries(candidate)) {
    const baselineAbilityMap = baseline[resource];
    if (!baselineAbilityMap) {
      return `resource ${resource} not in baseline`;
    }
    for (const [ability, candidateCaveatsRaw] of Object.entries(
      candidateAbilityMap,
    )) {
      const baselineCaveats = baselineAbilityMap[ability];
      if (baselineCaveats === undefined) {
        return `ability ${ability} on ${resource} not in baseline`;
      }
      const candidateCaveats: unknown[] = Array.isArray(candidateCaveatsRaw)
        ? (candidateCaveatsRaw as unknown[])
        : [];
      // Sol final continuation contract requirement 3: EXACT multiset
      // equality on surviving abilities. Any drift in caveat counts (an
      // added caveat, a removed caveat, a replaced caveat, or a changed
      // duplicate count) is a violation. Whole-ability removal is
      // permitted at the enclosing loop level: it simply does not appear
      // in the candidate.
      const baselineCounts = new Map<string, number>();
      for (const c of baselineCaveats) {
        const key = stableStringify(c);
        baselineCounts.set(key, (baselineCounts.get(key) ?? 0) + 1);
      }
      const candidateCounts = new Map<string, number>();
      for (const c of candidateCaveats) {
        const key = stableStringify(c);
        candidateCounts.set(key, (candidateCounts.get(key) ?? 0) + 1);
      }
      if (baselineCounts.size !== candidateCounts.size) {
        return `caveats on ${ability}@${resource} differ (baseline has ${baselineCounts.size} distinct caveats, candidate has ${candidateCounts.size})`;
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
      // Any candidate caveat not in baseline is caught by the size check
      // above OR by the count comparison (candidateN>0, baselineN=0). We
      // still walk candidateCounts to surface the specific ADD case with
      // a clearer message when only a new caveat was introduced.
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

export function consumeAuthorizationContext(
  input: ConsumeInput,
): ConsumeSuccess | ConsumeFailure {
  const now = Date.now();
  pruneExpired(now);
  const stored = store.get(input.token);
  if (!stored) {
    return { ok: false, error: "context-not-found", message: "Authorization context not found." };
  }
  // Single-use: consume immediately so replay attempts miss.
  store.delete(input.token);

  if (stored.expiresAt <= now) {
    return { ok: false, error: "context-expired", message: "Authorization context expired." };
  }
  if (stored.userId !== input.userId) {
    return { ok: false, error: "user-mismatch", message: "Authorization context bound to a different user." };
  }
  if (input.keyId !== undefined && stored.keyId !== input.keyId) {
    return { ok: false, error: "key-mismatch", message: "Authorization context bound to a different key." };
  }
  if (stored.keyAddress !== input.keyAddress.toLowerCase()) {
    return { ok: false, error: "key-mismatch", message: "Authorization context bound to a different key address." };
  }
  const candidateJwkDigest = digestJwk(input.jwk);
  if (!constantTimeEqual(stored.jwkDigest, candidateJwkDigest)) {
    return { ok: false, error: "jwk-mismatch", message: "Session JWK does not match the prepared context." };
  }
  if (stored.host !== input.host) {
    return { ok: false, error: "host-mismatch", message: "Host does not match the prepared context." };
  }
  if (stored.spaceId !== input.spaceId) {
    return { ok: false, error: "space-mismatch", message: "spaceId does not match the prepared context." };
  }
  if (!constantTimeEqual(stored.immutableFieldsDigest, input.candidateImmutableFieldsDigest)) {
    return {
      ok: false,
      error: "immutable-fields-changed",
      message: "SIWE immutable fields (domain, issuedAt, expirationTime, nonce, chainId, spaceId, address) do not match the prepared context.",
    };
  }
  // Sol MAJOR-4: attenuation-subset check (preferred). When callers pass a
  // candidate + baseline attenuation, we cross-check the baseline against
  // the stored digest, then verify the candidate is a strict subset of the
  // baseline INCLUDING caveats. This replaces the tautological equality
  // digest check that previously compared two derivations of the SAME
  // caveat-stripped `entries`.
  if (input.candidateAttenuation !== undefined) {
    if (input.baselineAttenuation === undefined) {
      return {
        ok: false,
        error: "baseline-digest-mismatch",
        message:
          "candidateAttenuation supplied without baselineAttenuation — cannot perform subset check.",
      };
    }
    const baselineDigest = digestFullRecapAttenuation(input.baselineAttenuation);
    if (!constantTimeEqual(stored.baselineAbilitiesDigest, baselineDigest)) {
      return {
        ok: false,
        error: "baseline-digest-mismatch",
        message:
          "baselineAttenuation supplied to consume does not match the digest bound at /prepare.",
      };
    }
    const subsetFailure = attenuationSubsetFailure(
      input.candidateAttenuation,
      input.baselineAttenuation,
    );
    if (subsetFailure) {
      return {
        ok: false,
        error: "candidate-broadens-baseline",
        message: `Candidate ReCap broadens the prepared baseline: ${subsetFailure}`,
      };
    }
  } else if (
    input.candidateAbilitiesDigest !== undefined &&
    input.candidateAbilitiesDigest !== null &&
    !constantTimeEqual(stored.baselineAbilitiesDigest, input.candidateAbilitiesDigest)
  ) {
    // Legacy equality-only path: kept for tests that predate the
    // attenuation-based subset check. Production callers always send
    // `candidateAttenuation` + `baselineAttenuation`.
    return {
      ok: false,
      error: "baseline-digest-mismatch",
      message: "Candidate abilities digest does not match the prepared baseline.",
    };
  }
  const allowed = new Set(stored.allowedActionIds);
  const initialSelection = new Set(stored.initialSelectionActionIds);
  for (const actionId of input.selectedActionIds) {
    if (!allowed.has(actionId)) {
      return {
        ok: false,
        error: "action-not-in-baseline",
        message: `Selected action ${actionId} is not part of the prepared baseline.`,
      };
    }
    // Sol CRITICAL-2: the caller may only sign a SUBSET of the initial
    // selection bound at /prepare. Broadening the initial selection at
    // /complete would let a CLI request grants the user narrowed away
    // earlier, so any action outside the bound initial selection is a
    // hard fail. For flows where /prepare passes allowedActionIds =
    // initialSelectionActionIds (widget baseline path), this collapses
    // to the pre-existing subset-of-baseline invariant.
    if (!initialSelection.has(actionId)) {
      return {
        ok: false,
        error: "action-not-in-initial-selection",
        message: `Selected action ${actionId} is not part of the initial selection bound at /prepare.`,
      };
    }
  }
  for (const actionId of input.requiredActionIds) {
    if (!input.selectedActionIds.has(actionId)) {
      return {
        ok: false,
        error: "required-action-missing",
        message: `Required action ${actionId} was removed from the selection.`,
      };
    }
  }
  return {
    ok: true,
    allowedActionIds: allowed,
    selectedActionIds: input.selectedActionIds,
    baselineAbilitiesDigest: stored.baselineAbilitiesDigest,
    spaceId: stored.spaceId,
    expirationTime: stored.expirationTime,
    originalSiwe: stored.originalSiwe,
    jwk: stored.jwk,
    keyId: stored.keyId,
    host: stored.host,
  };
}

export interface PeekSuccess {
  ok: true;
  value: {
    userId: string;
    keyId: string;
    keyAddress: string;
    host: string;
    spaceId: string;
    originalSiwe: string;
    jwk: unknown;
    expirationTime: string;
    allowedActionIds: string[];
    initialSelectionActionIds: string[];
  };
}

export interface PeekFailure {
  ok: false;
  error: ConsumeError;
  message: string;
}

/**
 * Non-consuming lookup for a stored authorization context. Returns the bound
 * fields so a caller can reconstruct the immutable-fields digest before
 * invoking `consumeAuthorizationContext`. This exists because
 * `/authorize-sign` needs to look up the bound key row (via keyAddress)
 * before it can compute the candidate immutable-fields digest for consume.
 *
 * Peek DOES NOT extend the token TTL and DOES NOT reveal the token itself.
 * It only surfaces the bound facts that the caller supplied at issue time.
 * Callers MUST follow up with `consumeAuthorizationContext` — the peek is
 * purely a lookup, never an authority.
 */
export function peekAuthorizationContext(token: string): PeekSuccess | PeekFailure {
  const now = Date.now();
  pruneExpired(now);
  const stored = store.get(token);
  if (!stored) {
    return { ok: false, error: "context-not-found", message: "Authorization context not found." };
  }
  if (stored.expiresAt <= now) {
    return { ok: false, error: "context-expired", message: "Authorization context expired." };
  }
  return {
    ok: true,
    value: {
      userId: stored.userId,
      keyId: stored.keyId,
      keyAddress: stored.keyAddress,
      host: stored.host,
      spaceId: stored.spaceId,
      originalSiwe: stored.originalSiwe,
      jwk: stored.jwk,
      expirationTime: stored.expirationTime,
      allowedActionIds: [...stored.allowedActionIds],
      initialSelectionActionIds: [...stored.initialSelectionActionIds],
    },
  };
}

/** Test helper — clears all stored contexts. Not exported to production. */
export function _resetAuthorizationContextStoreForTests(): void {
  store.clear();
  previewApprovals.clear();
}

// ============================================================================
// Preview approval tokens (Sol CRITICAL-1).
//
// The /authorize-sign-preview route returns exactly the bytes the server
// would sign for a given (context-token, selectedActionIds) pair. Without a
// preview-approval token that seals BOTH the selection and the candidate
// bytes, /authorize-sign could independently accept a different
// selectedActionIds and sign different bytes than were previewed.
//
// A preview-approval token binds:
//   - the parent authorization context token
//   - the exact selectedActionIds the preview evaluated
//   - the exact signedMessage bytes the preview would sign
//   - the authenticated user
//
// /authorize-sign requires the preview-approval token AND enforces that the
// finalized selection + candidate bytes match the sealed values byte-for-byte.
// The token is single-use, short-lived, and non-transferable across users.
// ============================================================================

const PREVIEW_APPROVAL_TTL_MS = 5 * 60 * 1000;

interface StoredPreviewApproval {
  token: string;
  createdAt: number;
  expiresAt: number;
  authorizationContextToken: string;
  userId: string;
  keyAddress: string;
  selectedActionIds: string[]; // sorted for stable comparison
  signedMessageDigest: string;
  signedMessage: string;
}

const previewApprovals = new Map<string, StoredPreviewApproval>();

function prunePreviewApprovals(now: number) {
  for (const [tok, ap] of previewApprovals) {
    if (ap.expiresAt <= now) previewApprovals.delete(tok);
  }
}

export interface PreviewApprovalIssueInput {
  authorizationContextToken: string;
  userId: string;
  keyAddress: string;
  selectedActionIds: Set<string>;
  signedMessage: string;
}

export interface PreviewApprovalToken {
  token: string;
  expiresAt: string;
  signedMessageDigest: string;
}

export function issuePreviewApproval(
  input: PreviewApprovalIssueInput,
): PreviewApprovalToken {
  const now = Date.now();
  prunePreviewApprovals(now);
  const token = `okp_${randomUUID().replace(/-/g, "")}${randomUUID().replace(/-/g, "")}`;
  const digest = sha256Hex(input.signedMessage);
  const stored: StoredPreviewApproval = {
    token,
    createdAt: now,
    expiresAt: now + PREVIEW_APPROVAL_TTL_MS,
    authorizationContextToken: input.authorizationContextToken,
    userId: input.userId,
    keyAddress: input.keyAddress.toLowerCase(),
    selectedActionIds: [...input.selectedActionIds].sort(),
    signedMessageDigest: digest,
    signedMessage: input.signedMessage,
  };
  previewApprovals.set(token, stored);
  return {
    token,
    expiresAt: new Date(stored.expiresAt).toISOString(),
    signedMessageDigest: digest,
  };
}

export type PreviewApprovalConsumeError =
  | "preview-approval-not-found"
  | "preview-approval-expired"
  | "preview-approval-user-mismatch"
  | "preview-approval-context-mismatch"
  | "preview-approval-selection-mismatch"
  | "preview-approval-bytes-mismatch";

export interface PreviewApprovalConsumeInput {
  token: string;
  authorizationContextToken: string;
  userId: string;
  selectedActionIds: Set<string>;
  /** The candidate signedMessage /authorize-sign is about to sign. */
  candidateSignedMessage: string;
}

export interface PreviewApprovalConsumeSuccess {
  ok: true;
  signedMessage: string;
  selectedActionIds: Set<string>;
  keyAddress: string;
}

export interface PreviewApprovalConsumeFailure {
  ok: false;
  error: PreviewApprovalConsumeError;
  message: string;
}

export function consumePreviewApproval(
  input: PreviewApprovalConsumeInput,
): PreviewApprovalConsumeSuccess | PreviewApprovalConsumeFailure {
  const now = Date.now();
  prunePreviewApprovals(now);
  const stored = previewApprovals.get(input.token);
  if (!stored) {
    return {
      ok: false,
      error: "preview-approval-not-found",
      message: "Preview approval token not found.",
    };
  }
  // Single-use: delete before validation so replay attempts miss.
  previewApprovals.delete(input.token);
  if (stored.expiresAt <= now) {
    return {
      ok: false,
      error: "preview-approval-expired",
      message: "Preview approval expired.",
    };
  }
  if (stored.userId !== input.userId) {
    return {
      ok: false,
      error: "preview-approval-user-mismatch",
      message: "Preview approval bound to a different user.",
    };
  }
  if (stored.authorizationContextToken !== input.authorizationContextToken) {
    return {
      ok: false,
      error: "preview-approval-context-mismatch",
      message:
        "Preview approval was issued for a different authorization context.",
    };
  }
  // Sol CRITICAL-1: enforce EXACT selection equality between preview and
  // finalize. Any drift means the widget could sign bytes different from
  // what the user previewed.
  const candidateSorted = [...input.selectedActionIds].sort();
  if (candidateSorted.length !== stored.selectedActionIds.length) {
    return {
      ok: false,
      error: "preview-approval-selection-mismatch",
      message:
        "selectedActionIds at /authorize-sign does not match the preview approval.",
    };
  }
  for (let i = 0; i < candidateSorted.length; i++) {
    if (candidateSorted[i] !== stored.selectedActionIds[i]) {
      return {
        ok: false,
        error: "preview-approval-selection-mismatch",
        message:
          "selectedActionIds at /authorize-sign does not match the preview approval.",
      };
    }
  }
  // Sol CRITICAL-1: enforce EXACT signedMessage equality between preview
  // and finalize. Even one whitespace change indicates the server would
  // sign different bytes than the preview showed.
  const candidateDigest = sha256Hex(input.candidateSignedMessage);
  if (!constantTimeEqual(stored.signedMessageDigest, candidateDigest)) {
    return {
      ok: false,
      error: "preview-approval-bytes-mismatch",
      message:
        "Candidate signedMessage bytes do not match the preview approval.",
    };
  }
  return {
    ok: true,
    signedMessage: stored.signedMessage,
    selectedActionIds: new Set(stored.selectedActionIds),
    keyAddress: stored.keyAddress,
  };
}
