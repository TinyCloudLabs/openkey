import { appDisplayName } from '@openkey/capability-review';
import { checkRequesterScope, isRequesterScopePolicy, type RequesterScopePolicy, type RequesterScopeRequest } from './requester-scope-policy';

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

/**
 * TinyCloud One's stable request-signing keys (`did:key`), one per
 * deployment. Empty until One's key is set; another deployment (preview, dev)
 * lists its own in `VITE_TINYCLOUD_ONE_REQUESTER_DIDS`.
 */
export const TINYCLOUD_ONE_REQUESTER_DIDS: readonly string[] = [];
/** Add verified request signers here, one entry per line. */
export const VERIFIED_REQUESTERS: readonly VerifiedRequesterEntry[] = [];

/** A configured requester key: an Ed25519 `did:key` (`did:key:z6Mk…`). */
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

/**
 * Who is asking in a one-tap approval request. `issuer` is the request's
 * signer, which the API checks against the request's signature before `/load`
 * returns it; nothing else in a signed request names the requester. Only a
 * listed TinyCloud One key is named; null for every other signer, which the
 * page shows as not verified.
 */
export function approvalRequester(issuer: string, oneRequesterDids: readonly string[]): DelegateRequester | null {
  return oneRequesterDids.includes(issuer) ? TINYCLOUD_ONE_REQUESTER : null;
}

/**
 * Names a request only when its signing DID exactly matches a reviewed key and the request stays inside that key's
 * policy. `request` is the parsed request; without it (not loaded yet) no listed key is named. TinyCloud One keys
 * are named by key alone.
 */
export function verifiedApprovalRequester(
  issuer: string,
  oneRequesterDids: readonly string[],
  verifiedRequesters: readonly VerifiedRequesterEntry[],
  request: RequesterScopeRequest | null,
): DelegateRequester | null {
  const one = approvalRequester(issuer, oneRequesterDids);
  if (one) return one;
  if (request === null) return null;
  const entry = verifiedRequesters.find((requester) => requester.did === issuer && isVerifiedRequesterEntry(requester));
  if (!entry || !checkRequesterScope(entry.policy, request).ok) return null;
  return { displayName: entry.displayName, returnTo: entry.returnTo };
}
