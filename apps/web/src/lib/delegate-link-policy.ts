import { appDisplayName } from '@openkey/capability-review';
import {
  checkRequesterScope, isRequesterScopePolicy, leadingRefusal, requesterScopeRefusals,
  type RequesterScopePolicy, type RequesterScopeRefusal, type RequesterScopeRequest,
} from './requester-scope-policy';

/**
 * TC-547: what an ordinary `/delegate` link (one without a device
 * transaction) may ask for. Anyone can make such a link, so the page only
 * returns a signed delegation to this device (a loopback callback, as the
 * TinyCloud CLI uses) or to a registered app callback endpoint, and it flags
 * a TinyCloud node it does not recognize. Device links are bound by the
 * server-verified device request instead and do not use this policy.
 */

/**
 * App callback endpoints (HTTPS origin plus exact path; any query is allowed)
 * that may receive a delegation through a `/delegate` callback. Register an
 * app by adding its endpoint here, or, for another deployment, to
 * `VITE_DELEGATE_CALLBACK_URLS`.
 *  - Broad hosted TinyCloud MCP, the public personal-records plugin, and the
 *    personal-records addresses listed in the Claude, Grok and Muse directories.
 */
export const REGISTERED_CALLBACK_ENDPOINTS: readonly string[] = [
  'https://mcp.tinycloud.xyz/connect/callback',
  'https://mcp.tinycloud.xyz/chatgpt/connect/callback',
  'https://mcp.tinycloud.xyz/claude/connect/callback',
  'https://mcp.tinycloud.xyz/grok/connect/callback',
  'https://mcp.tinycloud.xyz/muse/connect/callback',
];

/**
 * TinyCloud nodes shown without a warning: the nodes OpenKey already trusts
 * for bootstrap (`TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS` in the API). The CLI and
 * hosted MCP default to the TEE node. Extra deployments can be listed in
 * `VITE_DELEGATE_NODE_ORIGINS`. Loopback nodes run on this device and are
 * also recognized.
 */
export const KNOWN_NODE_ORIGINS: readonly string[] = ['https://node.tinycloud.xyz', 'https://tee.node.tinycloud.xyz'];

const LOOPBACK_HOSTNAMES: Record<string, true> = { localhost: true, '127.0.0.1': true, '[::1]': true };

export function isLoopbackHostname(hostname: string): boolean {
  return Object.hasOwn(LOOPBACK_HOSTNAMES, hostname.toLowerCase());
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

/** HTTPS, or HTTP on a loopback host, with no embedded credentials. */
function isSafeTransport(url: URL): boolean {
  if (url.username || url.password) return false;
  return url.protocol === 'https:' || (url.protocol === 'http:' && isLoopbackHostname(url.hostname));
}

/** A configured origin: canonical HTTPS origin, e.g. `https://node.example`. */
export function isCanonicalHttpsOrigin(entry: string): boolean {
  const url = parseUrl(entry);
  return url !== null && url.protocol === 'https:' && url.origin === entry;
}

/**
 * A configured callback endpoint: canonical HTTPS URL with a path and no
 * credentials, query, or fragment, e.g. `https://app.example/callback`.
 */
export function isCanonicalHttpsEndpoint(entry: string): boolean {
  const url = parseUrl(entry);
  // href equal to origin + path rules out credentials, query, and fragment.
  return url !== null && url.protocol === 'https:' && url.pathname !== '/'
    && url.href === `${url.origin}${url.pathname}` && url.href === entry;
}

/**
 * The built-in entries plus a comma-separated configured list. Configured
 * entries that fail `isValid` are ignored.
 */
export function withConfiguredEntries(
  builtIn: readonly string[],
  configured: string | undefined,
  isValid: (entry: string) => boolean,
): string[] {
  const extra = (configured ?? '').split(',').map((entry) => entry.trim()).filter(isValid);
  return [...new Set([...builtIn, ...extra])];
}

export type DelegateCallbackCheck =
  | { ok: true; callback: string | null }
  | { ok: false; reason: string; endpoint?: string };

/**
 * Where the page may POST the signed delegation. No callback means the page
 * shows a paste code instead. Anything other than a loopback URL or a
 * registered app callback endpoint is refused.
 */
export function checkDelegateCallback(raw: string, registeredEndpoints: readonly string[]): DelegateCallbackCheck {
  if (!raw) return { ok: true, callback: null };
  const url = parseUrl(raw);
  if (!url || !isSafeTransport(url)) {
    return { ok: false, reason: 'This link asks OpenKey to send your delegation to an invalid callback address. Restart the command or app that opened this page.' };
  }
  if (isLoopbackHostname(url.hostname) || registeredEndpoints.includes(`${url.origin}${url.pathname}`)) {
    return { ok: true, callback: url.href };
  }
  return {
    ok: false,
    endpoint: `${url.origin}${url.pathname}`,
    reason: `This link asks OpenKey to send your delegation to ${url.origin}${url.pathname}, which is not a registered TinyCloud app. OpenKey only returns delegations to this device or to registered apps, so this request was refused.`,
  };
}

export type DelegateHostCheck =
  | { ok: true; host: string; recognized: boolean }
  | { ok: false; reason: string; hostname?: string };

/**
 * The TinyCloud node the delegation is activated on, which receives it.
 * Unsafe transports are refused; a node outside the known list (and not on
 * this device) is allowed but must be flagged to the owner.
 */
export function checkDelegateHost(raw: string, knownOrigins: readonly string[]): DelegateHostCheck {
  const url = parseUrl(raw);
  if (!url || !isSafeTransport(url)) {
    return { ok: false, hostname: url?.hostname, reason: 'This link names an invalid TinyCloud node. A node must be an HTTPS address. Restart the command or app that opened this page.' };
  }
  const bareOrigin = url.pathname === '/' && !url.search && !url.hash;
  const recognized = bareOrigin && (isLoopbackHostname(url.hostname) || knownOrigins.includes(url.origin));
  return { ok: true, host: raw, recognized };
}

export type DelegateRequester = { displayName: string; returnTo: string };

/** The CLI wording: loopback callbacks, no callback, and anything unmapped. */
export const CLI_REQUESTER: DelegateRequester = { displayName: 'TinyCloud CLI', returnTo: 'the CLI' };

/**
 * Who is asking, as the approval screen words it. Only the built-in
 * `REGISTERED_CALLBACK_ENDPOINTS` are named here, so a name appears only for an
 * exact, already-approved return address. It never comes from the link's
 * free-form parameters, and a callback added through
 * `VITE_DELEGATE_CALLBACK_URLS` gets no name.
 */
const REQUESTER_BY_CALLBACK_ENDPOINT: Record<string, DelegateRequester> = {
  'https://mcp.tinycloud.xyz/claude/connect/callback': { displayName: 'Claude via TinyCloud', returnTo: 'Claude' },
  'https://mcp.tinycloud.xyz/grok/connect/callback': { displayName: 'Grok via TinyCloud', returnTo: 'Grok' },
  'https://mcp.tinycloud.xyz/muse/connect/callback': { displayName: 'Muse via TinyCloud', returnTo: 'Muse' },
  'https://mcp.tinycloud.xyz/chatgpt/connect/callback': { displayName: 'ChatGPT via TinyCloud', returnTo: 'ChatGPT' },
  'https://mcp.tinycloud.xyz/connect/callback': { displayName: 'TinyCloud MCP', returnTo: 'your MCP client' },
};

/**
 * The requester name and return target for an approved callback (the
 * `callback` of a passing `checkDelegateCallback`). Loopback, absent and
 * unmapped callbacks keep the CLI wording.
 */
export function delegateRequester(approvedCallback: string | null): DelegateRequester {
  const url = approvedCallback ? parseUrl(approvedCallback) : null;
  // The caller passes an approved callback, but a name is not handed out on that assumption alone.
  if (!url || url.protocol !== 'https:' || !isSafeTransport(url)) return CLI_REQUESTER;
  const endpoint = `${url.origin}${url.pathname}`;
  return Object.hasOwn(REQUESTER_BY_CALLBACK_ENDPOINT, endpoint) ? REQUESTER_BY_CALLBACK_ENDPOINT[endpoint]! : CLI_REQUESTER;
}

/** The name and return line for a one-tap request signed by TinyCloud One's own key. */
export const TINYCLOUD_ONE_REQUESTER: DelegateRequester = { displayName: 'TinyCloud One', returnTo: 'TinyCloud One' };

/** Add verified request signers here, one entry per line. */
export const VERIFIED_REQUESTERS: readonly VerifiedRequesterEntry[] = [];

/** An Ed25519 `did:key` (`did:key:z6Mk…`). */
export function isEd25519DidKey(entry: string): boolean {
  return /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/.test(entry);
}
/** `policy` bounds what the key may ask for; a request outside it gets no verified name. */
export type VerifiedRequesterEntry = { did: string; displayName: string; returnTo: string; policy: RequesterScopePolicy };

/** Only reviewed Ed25519 keys with a well-formed scope policy and plain, unambiguous names may be listed. */
export function isVerifiedRequesterEntry(entry: VerifiedRequesterEntry): boolean {
  if (!isEd25519DidKey(entry.did) || !isRequesterScopePolicy(entry.policy)) return false;
  const name = appDisplayName(entry.displayName);
  if (name === null || name !== entry.displayName || appDisplayName(entry.returnTo) !== entry.returnTo) return false;
  const displayName = name.toLowerCase();
  const returnTo = entry.returnTo.toLowerCase();
  return displayName !== 'tinycloud one' && displayName !== 'tinycloud cli'
    && returnTo !== 'tinycloud one' && returnTo !== 'tinycloud cli';
}

/** A TinyCloud One key that is named only for a request inside its policy. */
export type OneVerifiedRequesterEntry = { did: string; policy: RequesterScopePolicy };

/**
 * TinyCloud One's reviewed request-signing key and the scope it may ask for. A key alone grants no verified name.
 */
export const TINYCLOUD_ONE_VERIFIED_REQUESTERS: readonly OneVerifiedRequesterEntry[] = [{
  did: 'did:key:z6Mkm7hJCGM9CygEBbAsnY25PxmwR3Ujp5ryZUHLH2ir56tF',
  policy: {
    maxLifetimeSeconds: 3600,
    rules: [
      { kind: 'path', service: 'tinycloud.kv', spaces: ['secrets'], actions: ['tinycloud.kv/get'], pathPrefixes: ['vault/secrets/'], segmentPatterns: ['^[A-Z][A-Z0-9_]*$'] },
      { kind: 'encryption-network', service: 'tinycloud.encryption', spaces: ['encryption'], actions: ['tinycloud.encryption/decrypt'], network: 'default', wholeNetwork: true, keyPrefixes: ['secrets/'], keyNamePattern: '^(?!scoped$)[a-z0-9][a-z0-9_-]*$' },
    ],
  },
}];

/** A well-formed One entry: an Ed25519 `did:key` and a valid policy. */
export function isOneVerifiedRequesterEntry(entry: OneVerifiedRequesterEntry): boolean {
  return isEd25519DidKey(entry.did) && isRequesterScopePolicy(entry.policy);
}

/**
 * Names a request only when its signing DID exactly matches a reviewed key and both what was requested and what is
 * signed stay inside that key's policy. No key is named without its policy, TinyCloud One's included: a key in
 * `oneRequesters` is named 'TinyCloud One' under its own policy. A key in both lists takes the One entry and its
 * policy. `request` is the parsed request and `signed` the scope of the prepared message (`signedScopeRequest`); with
 * either missing (not loaded or not prepared yet) no key is named.
 */
export function verifiedApprovalRequester(
  issuer: string,
  oneRequesters: readonly OneVerifiedRequesterEntry[],
  verifiedRequesters: readonly VerifiedRequesterEntry[],
  request: RequesterScopeRequest | null,
  signed: RequesterScopeRequest | null,
): DelegateRequester | null {
  if (request === null || signed === null) return null;
  const one = oneRequesters.find((requester) => requester.did === issuer);
  if (one) {
    if (!isOneVerifiedRequesterEntry(one) || !checkRequesterScope(one.policy, request).ok || !checkRequesterScope(one.policy, signed).ok) return null;
    return TINYCLOUD_ONE_REQUESTER;
  }
  const entry = verifiedRequesters.find((requester) => requester.did === issuer && isVerifiedRequesterEntry(requester));
  if (!entry || !checkRequesterScope(entry.policy, request).ok || !checkRequesterScope(entry.policy, signed).ok) return null;
  return { displayName: entry.displayName, returnTo: entry.returnTo };
}

/**
 * Why a listed signer's link is shown as not verified: the verified name of its entry and the reason to report, the
 * first by `leadingRefusal` among everything its request and its prepared message ask outside the entry's policy.
 * Null when the signer is not listed (or its entry is malformed), when neither scope is known, or when both scopes
 * are inside the policy. It names no requester: `verifiedApprovalRequester` alone decides that.
 */
export function requesterRefusal(
  issuer: string,
  oneRequesters: readonly OneVerifiedRequesterEntry[],
  verifiedRequesters: readonly VerifiedRequesterEntry[],
  request: RequesterScopeRequest | null,
  signed: RequesterScopeRequest | null,
): { app: string; reason: RequesterScopeRefusal } | null {
  const one = oneRequesters.find((requester) => requester.did === issuer);
  const entry = one ? null : verifiedRequesters.find((requester) => requester.did === issuer && isVerifiedRequesterEntry(requester));
  if (one && !isOneVerifiedRequesterEntry(one)) return null;
  const listed = one ? { app: TINYCLOUD_ONE_REQUESTER.displayName, policy: one.policy } : entry ? { app: entry.displayName, policy: entry.policy } : null;
  if (!listed) return null;
  const reason = leadingRefusal([request, signed].flatMap((scope) => (scope === null ? [] : requesterScopeRefusals(listed.policy, scope))));
  return reason === null ? null : { app: listed.app, reason };
}
