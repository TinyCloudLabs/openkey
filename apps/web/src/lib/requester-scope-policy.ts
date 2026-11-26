import { parseCapabilityReview, parseEncryptionResource, type SignerInfo } from '@openkey/capability-review';

/**
 * What a verified requester may ask for. A listed requester keeps its verified name only for a request inside its
 * policy; any other request from the same key is shown as not verified, with the reason from `checkRequesterScope`.
 *
 * A rule covers one service, and may pin the `spaces` a permission names (any space when absent).
 * - `path` rules match a resource path made of one of the `pathPrefixes` followed by one segment per entry of
 *   `segmentPatterns`. Each pattern is the source of an anchored regular expression and is the allowed-character
 *   list for its segment (for a secret name, `^[A-Z][A-Z0-9_]*$`, the SDK's secret-name rule). A pattern is only
 *   literal characters and character classes, after `^` and before `$`, with one optional `(?!word$)` lookahead.
 *   A class holds single letters, digits and `_`, and ranges inside one type (`A-Z`, `a-z`, `0-9`; never `0-z` or
 *   `Z-a`). Each atom has at most a `*`, `+` or `{n,m}` quantifier; a pattern has at most two unbounded atoms (`*`,
 *   `+`, `{n,}`), at most four quantified atoms and no count above 64. Any other form (`.`, `\W`, `?`, an
 *   alternation, a group) is not a valid pattern. Apart from the patterns, the whole path must be plain segments of
 *   letters, digits, `_` and `-` before a pattern is read, so a path with a query, fragment or escape never reaches one.
 * - `encryption-network` rules match an encryption resource on one network: the network itself when `wholeNetwork`
 *   is set, and a key whose path is one of the `keyPrefixes` followed by one name that matches `keyNamePattern`
 *   (validated like a segment pattern). Prefixes and keys elsewhere on the network are outside.
 * Prefixes are written as `a/b/`: letters, digits, `_` and `-` only, each segment non-empty.
 * The owner inside an encryption resource is not compared with anyone here; `signedScopeRequest` refuses a signed
 * grant whose resource is not the signer's own.
 */
export type RequesterScopeRule =
  | { kind: 'path'; service: string; spaces?: readonly string[]; actions: readonly string[]; pathPrefixes: readonly string[]; segmentPatterns: readonly string[] }
  | { kind: 'encryption-network'; service: string; spaces?: readonly string[]; actions: readonly string[]; network: string; wholeNetwork: boolean; keyPrefixes: readonly string[]; keyNamePattern: string };

export type RequesterScopePolicy = {
  /** The longest grant the requester may ask for. */
  maxLifetimeSeconds: number;
  /** Every requested permission must fit one rule. */
  rules: readonly RequesterScopeRule[];
};

export type RequesterScopeRefusal =
  | 'malformed'
  | 'no-permissions'
  | 'lifetime'
  | 'service'
  | 'action'
  | 'space'
  | 'path'
  | 'renewal'
  | 'context';

export type RequesterScopeVerdict = { ok: true } | { ok: false; reason: RequesterScopeRefusal };

/** The parts of a parsed approval request the policy reads. Unknown JSON is checked, not trusted. */
export type RequesterScopeRequest = {
  permissions: unknown;
  grantLifetimeSeconds: unknown;
  renewal?: unknown;
  context?: unknown;
};

const NETWORK = /^[a-z0-9][a-z0-9-]*$/;
/** Segments of a prefix, and of any path that is matched: letters, digits, `_` and `-`. */
const PREFIX = /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*\/$/;
const PATH = /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
const LITERAL = '[A-Za-z0-9_-]';
/** A character class of letters, digits and `_`; a range stays inside one type (`A-Z`, `a-z`, `0-9`), `-` only last: `[A-Z0-9_]`, `[a-z0-9_-]`. */
const CLASS = '\\[(?:[A-Z]-[A-Z]|[a-z]-[a-z]|[0-9]-[0-9]|[A-Za-z0-9_])+-?\\]';
/** One atom: a class or a literal character, with at most a `*`, `+`, `{n}` or `{n,m}` quantifier. */
const ATOM = `(?:${CLASS}|${LITERAL})(?:[*+]|\\{\\d{1,3}(?:,\\d{0,3})?\\})?`;
/** A pattern is `^`, an optional `(?!word$)` lookahead, then one or more atoms, then `$`: nothing else. */
const SEGMENT_PATTERN = new RegExp(`^\\^(?:\\(\\?!${LITERAL}+\\$\\))?(?:${ATOM})+\\$$`);
/** What no segment pattern may admit, alone or between letters: query, fragment, escape, separator, dot, space, control. */
const FORBIDDEN_IN_SEGMENT = ['?', '#', '%', '/', '\\', '.', ' ', '\t', '\n', '\r', '\f', '\v', '\u0000', '\u001f', '\u007f', '\u00a0', '\u2028', '\u2029', '\ufeff', ':', ';', '@', '&', '=', '+', '$', ',', '*', '!', "'", '"', '<', '>', '|', '~', '`', '^', '(', ')', '[', ']', '{', '}'];

/** At most this many `*`, `+` or `{n,}` atoms per pattern: each is an unbounded repeat, and a run of them backtracks polynomially. */
const MAX_UNBOUNDED_ATOMS = 2;
/**
 * At most this many quantified atoms per pattern, bounded or not. A run of `[A-Z]{0,64}` atoms backtracks
 * polynomially too: 8 of them take about 2 s on a 40-character miss.
 */
const MAX_QUANTIFIED_ATOMS = 4;
/** The largest count a `{n}`, `{n,m}` or `{n,}` quantifier may carry. */
const MAX_REPEAT = 64;

/** Whether the quantifiers of an already-valid source stay inside the three limits above. */
function repeatsFit(source: string): boolean {
  // Classes and the lookahead hold only letters, digits, `_` and `-`, so every `*`, `+` and `{` here is a quantifier.
  let unbounded = (source.match(/[*+]/g) ?? []).length;
  let quantified = unbounded;
  for (const [, min, comma, max] of source.matchAll(/\{(\d+)(,)?(\d*)\}/g)) {
    quantified += 1;
    if (Number(min) > MAX_REPEAT) return false;
    if (comma && max === '') unbounded += 1;
    else if (comma && Number(max) > MAX_REPEAT) return false;
  }
  return unbounded <= MAX_UNBOUNDED_ATOMS && quantified <= MAX_QUANTIFIED_ATOMS;
}

/**
 * Whether a source is a segment pattern: the bounded literal-and-class form above, in which a class holds only single
 * characters and ranges inside one of `A-Z`, `a-z` or `0-9` (so no range can reach `? : @ \` or any other symbol).
 * Such a pattern cannot name a query, fragment, escape, separator, dot, whitespace or control character, and the
 * check below also refuses an empty segment. It carries at most two unbounded atoms, at most four quantified atoms
 * and no count above 64. The sample characters are a second check on the compiled pattern.
 */
function isSegmentPattern(source: unknown): source is string {
  if (typeof source !== 'string' || source.length > 200 || !SEGMENT_PATTERN.test(source) || !repeatsFit(source)) return false;
  let pattern: RegExp;
  try {
    pattern = new RegExp(source);
  } catch {
    return false;
  }
  if (pattern.test('')) return false;
  return !FORBIDDEN_IN_SEGMENT.some((char) => ['A', 'a', '0', '_', '-'].some((letter) =>
    pattern.test(char) || pattern.test(`${letter}${char}`) || pattern.test(`${char}${letter}`) || pattern.test(`${letter}${char}${letter}`)));
}

/** Whether a policy is well formed: a bounded lifetime and at least one precise rule. */
export function isRequesterScopePolicy(policy: RequesterScopePolicy | null | undefined): boolean {
  if (!policy || typeof policy !== 'object') return false;
  if (!Number.isSafeInteger(policy.maxLifetimeSeconds) || policy.maxLifetimeSeconds <= 0) return false;
  if (!Array.isArray(policy.rules) || policy.rules.length === 0) return false;
  return policy.rules.every((rule) => {
    if (!rule || typeof rule !== 'object') return false;
    if (typeof rule.service !== 'string' || rule.service === '') return false;
    if (!Array.isArray(rule.actions) || rule.actions.length === 0 || rule.actions.some((action: unknown) => typeof action !== 'string' || action === '')) return false;
    if (rule.spaces !== undefined && (!Array.isArray(rule.spaces) || rule.spaces.length === 0 || rule.spaces.some((space: unknown) => typeof space !== 'string' || space === ''))) return false;
    if (rule.kind === 'path') {
      return Array.isArray(rule.pathPrefixes) && rule.pathPrefixes.length > 0 && rule.pathPrefixes.every((prefix: unknown) => typeof prefix === 'string' && PREFIX.test(prefix)) &&
        Array.isArray(rule.segmentPatterns) && rule.segmentPatterns.length > 0 && rule.segmentPatterns.every(isSegmentPattern);
    }
    if (rule.kind === 'encryption-network') {
      return typeof rule.network === 'string' && NETWORK.test(rule.network) && typeof rule.wholeNetwork === 'boolean' &&
        Array.isArray(rule.keyPrefixes) && rule.keyPrefixes.every((prefix: unknown) => typeof prefix === 'string' && PREFIX.test(prefix)) &&
        (rule.wholeNetwork || rule.keyPrefixes.length > 0) && isSegmentPattern(rule.keyNamePattern);
    }
    return false;
  });
}

/**
 * The most characters a path may carry after its prefix, so no more than this many reach a segment pattern. A miss
 * costs time in proportion to a power of the length it is matched against, and the key paths this policy
 * also reads stop at the same 255.
 */
const MAX_PATH_LENGTH = 255;

export function pathFits(rule: RequesterScopeRule, path: string): boolean {
  if (rule.kind === 'path') {
    return rule.pathPrefixes.some((prefix) => {
      if (!path.startsWith(prefix)) return false;
      const rest = path.slice(prefix.length);
      // Length before any pattern runs: a longer rest is refused without being matched.
      if (rest.length > MAX_PATH_LENGTH) return false;
      // The whole path is plain characters, so nothing below sees a query, fragment, escape or dot segment.
      if (!PATH.test(path)) return false;
      const segments = rest.split('/');
      return segments.length === rule.segmentPatterns.length && segments.every((segment, index) => new RegExp(rule.segmentPatterns[index]!).test(segment));
    });
  }
  const resource = parseEncryptionResource(path);
  if (resource?.network !== rule.network) return false;
  if (resource.kind === 'network') return rule.wholeNetwork;
  if (resource.kind !== 'key') return false;
  const key = new RegExp(rule.keyNamePattern);
  return rule.keyPrefixes.some((prefix) => resource.keyPath.startsWith(prefix) && key.test(resource.keyPath.slice(prefix.length)));
}

/** Whether a request stays inside a requester's policy, and the first reason when it does not. */
export function checkRequesterScope(policy: RequesterScopePolicy, request: RequesterScopeRequest): RequesterScopeVerdict {
  const refuse = (reason: RequesterScopeRefusal): RequesterScopeVerdict => ({ ok: false, reason });
  if (!isRequesterScopePolicy(policy)) return refuse('malformed');
  const { permissions, grantLifetimeSeconds } = request;
  if (!Array.isArray(permissions) || typeof grantLifetimeSeconds !== 'number' || !Number.isSafeInteger(grantLifetimeSeconds) || grantLifetimeSeconds <= 0) {
    return refuse('malformed');
  }
  if (request.renewal !== undefined) return refuse('renewal');
  if (request.context !== undefined) return refuse('context');
  if (permissions.length === 0) return refuse('no-permissions');
  if (grantLifetimeSeconds > policy.maxLifetimeSeconds) return refuse('lifetime');
  for (const permission of permissions) {
    if (!permission || typeof permission !== 'object') return refuse('malformed');
    // Server JSON of unknown shape; each field is type-checked below before use.
    const fields = permission as Record<string, unknown>;
    const { service, path, actions } = fields;
    if (typeof service !== 'string' || typeof path !== 'string' || !Array.isArray(actions) || actions.length === 0 ||
      actions.some((action) => typeof action !== 'string')) {
      return refuse('malformed');
    }
    const sameService = policy.rules.filter((rule) => rule.service === service);
    if (sameService.length === 0) return refuse('service');
    const allowedActions = sameService.filter((rule) => actions.every((action) => rule.actions.includes(action as string)));
    if (allowedActions.length === 0) return refuse('action');
    const space = fields.space;
    const inSpace = allowedActions.filter((rule) => rule.spaces === undefined || (typeof space === 'string' && rule.spaces.includes(space)));
    if (inSpace.length === 0) return refuse('space');
    if (!inSpace.some((rule) => pathFits(rule, path))) return refuse('path');
  }
  return { ok: true };
}

/** A grant of the prepared (signed) message, as the review model holds it: the fields the policy needs. */
export type SignedGrant = {
  service: string;
  /** A space URI such as `tinycloud:pkh:eip155:1:0x…:secrets`; for an encryption resource, the resource URN itself. */
  space: string;
  path: string;
  ownedBySelf: boolean | null;
  actions: readonly { ability: string }[];
  /** True when the ability's service and the resource's service segment disagree. */
  serviceMismatch?: boolean;
};

/**
 * The policy input for what is actually signed, from the review model's grants and the signed lifetime. A grant
 * is written the way a request writes it: the space by its last segment (`secrets`), and an encryption resource by
 * its URN in `path` with the space `encryption`. Null when the lifetime is unknown, or a grant is not known to be the
 * signer's own resource (`ownedBySelf` is not true) or has a service that disagrees with its resource, so no listed
 * key is named for it.
 */
export function signedScopeRequest(grants: readonly SignedGrant[], lifetimeSeconds: number | null): RequesterScopeRequest | null {
  if (lifetimeSeconds === null || grants.some((grant) => grant.ownedBySelf !== true || grant.serviceMismatch === true)) return null;
  const permissions = grants.map((grant) => {
    const actions = grant.actions.map((action) => action.ability);
    if (grant.service === 'tinycloud.encryption') return { service: grant.service, space: 'encryption', path: grant.space, actions };
    return { service: grant.service, space: grant.space.startsWith('tinycloud:') ? grant.space.slice(grant.space.lastIndexOf(':') + 1) : grant.space, path: grant.path, actions };
  });
  return { permissions, grantLifetimeSeconds: lifetimeSeconds };
}

/**
 * The seconds of clock difference between the page and the server that prepared the message. A message prepared for
 * exactly a policy's maximum lifetime reads a little longer on a page whose clock runs behind; the signed lifetime is
 * that many seconds shorter than the time left, so such a message stays within the policy. Anything longer is refused.
 */
const SIGNED_LIFETIME_SLACK_SECONDS = 30;

/**
 * The policy input for a prepared SIWE message, read the way the review reads it: its recap grants and the time left
 * until Expiration Time, which is how long the grant can still be used (Issued At does not bound it), less
 * `SIGNED_LIFETIME_SLACK_SECONDS` and never below one second. `nowMs` is the clock, passed in so a test can fix it.
 * Null when the message is not a recap, has no expiry or is expired, or `signedScopeRequest` refuses it.
 */
export function signedScopeOfMessage(message: string, signer: SignerInfo, nowMs: number = Date.now()): RequesterScopeRequest | null {
  try {
    const model = parseCapabilityReview({
      message,
      signer,
      editable: false,
      metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
      reason: { text: '', source: 'none' },
      requester: {
        displayName: '', verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none', manifestId: null,
        manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false,
      },
    });
    if (model.protocol !== 'tinycloud-siwe-recap' || !model.immutable) return null;
    const left = Date.parse(model.immutable.expirationTime) - nowMs;
    if (!Number.isFinite(left) || left <= 0) return signedScopeRequest(model.permissions, null);
    return signedScopeRequest(model.permissions, Math.max(1, Math.ceil(left / 1000) - SIGNED_LIFETIME_SLACK_SECONDS));
  } catch {
    return null;
  }
}
