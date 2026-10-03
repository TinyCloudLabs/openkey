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
 *  - Hosted TinyCloud MCP.
 */
export const REGISTERED_CALLBACK_ENDPOINTS: readonly string[] = ['https://mcp.tinycloud.xyz/connect/callback'];

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
  | { ok: false; reason: string };

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
    reason: `This link asks OpenKey to send your delegation to ${url.origin}${url.pathname}, which is not a registered TinyCloud app. OpenKey only returns delegations to this device or to registered apps, so this request was refused.`,
  };
}

export type DelegateHostCheck =
  | { ok: true; host: string; recognized: boolean }
  | { ok: false; reason: string };

/**
 * The TinyCloud node the delegation is activated on, which receives it.
 * Unsafe transports are refused; a node outside the known list (and not on
 * this device) is allowed but must be flagged to the owner.
 */
export function checkDelegateHost(raw: string, knownOrigins: readonly string[]): DelegateHostCheck {
  const url = parseUrl(raw);
  if (!url || !isSafeTransport(url)) {
    return { ok: false, reason: 'This link names an invalid TinyCloud node. A node must be an HTTPS address. Restart the command or app that opened this page.' };
  }
  const bareOrigin = url.pathname === '/' && !url.search && !url.hash;
  const recognized = bareOrigin && (isLoopbackHostname(url.hostname) || knownOrigins.includes(url.origin));
  return { ok: true, host: raw, recognized };
}
