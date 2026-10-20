// TC-1632: server-checked QA exemption from the Turnstile step on new-account
// creation. Both must hold: the request presents the configured QA secret in
// the header, and the new account's email matches a QA-eligible pattern in the
// test-account registry (TEST_ACCOUNT_REGISTRY_JSON). The secret is the
// authority; a pattern never exempts an account by itself. Accepted only on the
// sign-in/email-otp new-account branch, which marks the single-use sign-up token
// server-side.
import { createHash, timingSafeEqual } from 'node:crypto';

export type TestAccountRegistry = {
  userIds: readonly string[];
  clientIds: readonly string[];
  /** Lowercase domains of QA-eligible addresses. Narrows the scoreboard SQL prefilter. */
  emailDomains: readonly string[];
  qaEligiblePatterns: readonly RegExp[];
};

export type RegistryLoad = { registry: TestAccountRegistry; problem: boolean };

const EMPTY_REGISTRY: TestAccountRegistry = { userIds: [], clientIds: [], emailDomains: [], qaEligiblePatterns: [] };
const INVALID_REGISTRY: RegistryLoad = { registry: EMPTY_REGISTRY, problem: true };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

/**
 * Parses the registry JSON from TEST_ACCOUNT_REGISTRY_JSON. Unset means no registry
 * and is not a problem. Bad JSON, a bad shape, or an uncompilable pattern yields an
 * empty registry (no exemptions, no exclusions) with problem set. Never throws.
 */
export function parseTestAccountRegistry(raw: string | undefined): RegistryLoad {
  if (raw === undefined || raw.trim() === '') return { registry: EMPTY_REGISTRY, problem: false };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return INVALID_REGISTRY;
  }
  if (!isRecord(parsed)) return INVALID_REGISTRY;
  const { userIds, clientIds, patterns, emailDomains = [] } = parsed;
  if (!isStringArray(userIds) || !isStringArray(clientIds) || !isStringArray(emailDomains) || !Array.isArray(patterns)) {
    return INVALID_REGISTRY;
  }
  const qaEligiblePatterns: RegExp[] = [];
  for (const pattern of patterns) {
    if (!isRecord(pattern)) return INVALID_REGISTRY;
    const { regex, qaEligible } = pattern;
    if (typeof regex !== 'string' || typeof qaEligible !== 'boolean') return INVALID_REGISTRY;
    let compiled: RegExp;
    try {
      compiled = new RegExp(regex);
    } catch {
      return INVALID_REGISTRY;
    }
    if (qaEligible) qaEligiblePatterns.push(compiled);
  }
  const domains = emailDomains.map((domain) => domain.toLowerCase());
  return { registry: { userIds, clientIds, emailDomains: domains, qaEligiblePatterns }, problem: false };
}

let cachedRaw: string | undefined;
let cachedLoad: RegistryLoad | undefined;

/** The registry from the environment, parsed once per distinct value. */
export function loadTestAccountRegistry(env: NodeJS.ProcessEnv = process.env): RegistryLoad {
  const raw = env.TEST_ACCOUNT_REGISTRY_JSON;
  if (cachedLoad === undefined || raw !== cachedRaw) {
    cachedRaw = raw;
    cachedLoad = parseTestAccountRegistry(raw);
  }
  return cachedLoad;
}

export const QA_REGISTRATION_HEADER = 'x-openkey-qa-registration';
// 32 random bytes, base64url-encoded. Shorter values are treated as unset.
export const QA_SECRET_MIN_LENGTH = 43;

function digest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

function tooShort(value: string | undefined): boolean {
  return value !== undefined && value !== '' && value.length < QA_SECRET_MIN_LENGTH;
}

/** True when a configured QA secret is shorter than the minimum. Such a secret is ignored. */
export function qaRegistrationSecretTooShort(env: NodeJS.ProcessEnv = process.env): boolean {
  return tooShort(env.OPENKEY_QA_REGISTRATION_SECRET) || tooShort(env.OPENKEY_QA_REGISTRATION_SECRET_PREVIOUS);
}

/**
 * True only when the presented value equals the current or previous secret,
 * so a secret can be rotated without a flag day. Both configured secrets are
 * compared on every call, and digests are compared so length does not leak.
 * An unset or too-short secret never matches.
 */
export function qaRegistrationAuthorized(presented: string | null, env: NodeJS.ProcessEnv = process.env): boolean {
  if (!presented) return false;
  const candidate = digest(presented);
  let matched = false;
  for (const secret of [env.OPENKEY_QA_REGISTRATION_SECRET, env.OPENKEY_QA_REGISTRATION_SECRET_PREVIOUS]) {
    if (secret && secret.length >= QA_SECRET_MIN_LENGTH && timingSafeEqual(candidate, digest(secret))) matched = true;
  }
  return matched;
}

/**
 * True when the email matches a QA-eligible pattern in the registry. Only
 * meaningful together with the secret.
 */
export function qaEligibleEmail(
  email: string,
  patterns: readonly RegExp[] = loadTestAccountRegistry().registry.qaEligiblePatterns,
): boolean {
  const normalized = email.toLowerCase();
  return patterns.some((pattern) => pattern.test(normalized));
}
