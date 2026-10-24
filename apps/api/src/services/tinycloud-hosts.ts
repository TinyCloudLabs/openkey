// TinyCloud nodes OpenKey may sign for or host spaces on. Shared by the
// bootstrap flow and the native delegation client ceiling.
export const DEFAULT_TINYCLOUD_BOOTSTRAP_HOST = 'https://node.tinycloud.xyz';
export const TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS: ReadonlySet<string> = new Set([
  DEFAULT_TINYCLOUD_BOOTSTRAP_HOST,
  'https://tee.node.tinycloud.xyz',
]);

export const LOCAL_HOSTNAMES: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]']);

export function localHostsAllowed(): boolean {
  return process.env.NODE_ENV !== 'production' && process.env.TEE_MODE !== 'production';
}

// Printable ASCII, no space. Checked before lowercasing: String#toLowerCase
// maps some non-ASCII (U+212A KELVIN SIGN -> "k") onto ASCII.
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;

/**
 * The configured bootstrap host when `raw` names an allowlisted TinyCloud
 * node, otherwise null (TC-943). Both allowlisted names reach the same node,
 * so either one maps to `configuredHost`, which keys bootstrap state.
 * Accepts only `https://<allowlisted host>` with an optional single trailing
 * slash, in any ASCII case. The parser never makes an input acceptable: the
 * input string itself must equal an allowlisted origin. A configured host
 * outside the allowlist (local dev) matches only itself, exactly.
 */
export function canonicalTrustedTinyCloudHost(raw: unknown, configuredHost: string): string | null {
  if (typeof raw !== 'string') return null;
  if (!TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(configuredHost)) {
    return raw === configuredHost ? configuredHost : null;
  }
  if (!PRINTABLE_ASCII.test(raw)) return null;
  const candidate = (raw.endsWith('/') ? raw.slice(0, -1) : raw).toLowerCase();
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.origin !== candidate) return null;
  return TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(candidate) ? configuredHost : null;
}

/**
 * Whether OpenKey's server may send a session delegation to `raw` (TC-1949): an
 * allowlisted TinyCloud node, or a loopback origin outside production.
 */
export function isKnownTinyCloudActivationHost(raw: unknown): boolean {
  if (canonicalTrustedTinyCloudHost(raw, DEFAULT_TINYCLOUD_BOOTSTRAP_HOST) !== null) return true;
  if (typeof raw !== 'string' || !localHostsAllowed()) return false;
  const origin = raw.endsWith('/') ? raw.slice(0, -1) : raw;
  try {
    const url = new URL(origin);
    return (url.protocol === 'http:' || url.protocol === 'https:') &&
      LOCAL_HOSTNAMES.has(url.hostname) &&
      url.origin === origin;
  } catch {
    return false;
  }
}
