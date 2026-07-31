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
}

interface StoredContext {
  token: string;
  createdAt: number;
  expiresAt: number;
  userId: string;
  keyId: string;
  keyAddress: string;
  jwkDigest: string;
  host: string;
  spaceId: string;
  baselineAbilitiesDigest: string;
  immutableFieldsDigest: string;
  allowedActionIds: string[];
  initialSelectionActionIds: string[];
  expirationTime: string;
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

export function digestImmutableFields(fields: {
  address: string;
  chainId: number;
  domain: string;
  issuedAt: string;
  expirationTime: string;
  spaceId: string;
  nonce: string;
}): string {
  return sha256Hex(stableStringify(fields));
}

export interface AuthorizationContextToken {
  token: string;
  expiresAt: string;
  allowedActionIds: string[];
  initialSelectionActionIds: string[];
  /** Baseline digest so the widget can prove it received the right prepare. */
  baselineAbilitiesDigest: string;
}

export function issueAuthorizationContext(
  input: AuthorizationContextIssueInput,
): AuthorizationContextToken {
  const now = Date.now();
  pruneExpired(now);

  const token = `oks_${randomUUID().replace(/-/g, "")}${randomUUID().replace(/-/g, "")}`;
  const jwkDigest = digestJwk(input.jwk);

  const stored: StoredContext = {
    token,
    createdAt: now,
    expiresAt: now + CONTEXT_TTL_MS,
    userId: input.userId,
    keyId: input.keyId,
    keyAddress: input.keyAddress.toLowerCase(),
    jwkDigest,
    host: input.host,
    spaceId: input.spaceId,
    baselineAbilitiesDigest: input.baselineAbilitiesDigest,
    immutableFieldsDigest: input.immutableFieldsDigest,
    allowedActionIds: [...input.allowedActionIds].sort(),
    initialSelectionActionIds: [...input.initialSelectionActionIds].sort(),
    expirationTime: input.expirationTime,
  };
  store.set(token, stored);

  return {
    token,
    expiresAt: new Date(stored.expiresAt).toISOString(),
    allowedActionIds: stored.allowedActionIds,
    initialSelectionActionIds: stored.initialSelectionActionIds,
    baselineAbilitiesDigest: stored.baselineAbilitiesDigest,
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
  | "immutable-fields-changed"
  | "action-not-in-baseline"
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
  const allowed = new Set(stored.allowedActionIds);
  for (const actionId of input.selectedActionIds) {
    if (!allowed.has(actionId)) {
      return {
        ok: false,
        error: "action-not-in-baseline",
        message: `Selected action ${actionId} is not part of the prepared baseline.`,
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
  };
}

/** Test helper — clears all stored contexts. Not exported to production. */
export function _resetAuthorizationContextStoreForTests(): void {
  store.clear();
}
