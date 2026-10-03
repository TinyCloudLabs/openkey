/**
 * TC-547: what an ordinary `/delegate` link (one without a device
 * transaction) may ask for. Anyone can make such a link, so the page only
 * returns a signed delegation to this device (a loopback callback, as the
 * TinyCloud CLI uses) or to a registered app origin, and it flags a TinyCloud
 * node it does not recognize. Device links are bound by the server-verified
 * device request instead and do not use this policy.
 */

/**
 * App origins that may receive a delegation through a `/delegate` callback.
 * Register an app by adding its canonical HTTPS origin here (or, for a
 * non-production deployment, to `VITE_DELEGATE_CALLBACK_ORIGINS`).
 *  - https://mcp.tinycloud.xyz: hosted TinyCloud MCP (`/connect/callback`).
 */
export const REGISTERED_CALLBACK_ORIGINS: readonly string[] = ['https://mcp.tinycloud.xyz'];

/**
 * TinyCloud nodes shown without a warning. Extra deployments can be listed in
 * `VITE_DELEGATE_NODE_ORIGINS`. Loopback nodes run on this device and are
 * also recognized.
 */
export const KNOWN_NODE_ORIGINS: readonly string[] = ['https://node.tinycloud.xyz'];

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

/**
 * The built-in origins plus a comma-separated configured list. Configured
 * entries that are not canonical HTTPS origins are ignored.
 */
export function withConfiguredOrigins(builtIn: readonly string[], configured: string | undefined): string[] {
  const extra = (configured ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => {
      const url = parseUrl(entry);
      return url !== null && url.protocol === 'https:' && url.origin === entry;
    });
  return [...new Set([...builtIn, ...extra])];
}

export type DelegateCallbackCheck =
  | { ok: true; callback: string | null }
  | { ok: false; reason: string };

/**
 * Where the page may POST the signed delegation. No callback means the page
 * shows a paste code instead. Anything other than a loopback URL or a
 * registered app origin is refused.
 */
export function checkDelegateCallback(raw: string, registeredOrigins: readonly string[]): DelegateCallbackCheck {
  if (!raw) return { ok: true, callback: null };
  const url = parseUrl(raw);
  if (!url || !isSafeTransport(url)) {
    return { ok: false, reason: 'This link asks OpenKey to send your delegation to an invalid callback address. Restart the command or app that opened this page.' };
  }
  if (isLoopbackHostname(url.hostname) || registeredOrigins.includes(url.origin)) {
    return { ok: true, callback: url.href };
  }
  return {
    ok: false,
    reason: `This link asks OpenKey to send your delegation to ${url.origin}, which is not a registered TinyCloud app. OpenKey only returns delegations to this device or to registered apps, so this request was refused.`,
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
