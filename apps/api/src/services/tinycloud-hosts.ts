// TinyCloud nodes OpenKey may sign for or host spaces on. Shared by the
// bootstrap flow and the native delegation client ceiling.
export const DEFAULT_TINYCLOUD_BOOTSTRAP_HOST = 'https://node.tinycloud.xyz';
export const TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS: ReadonlySet<string> = new Set([
  DEFAULT_TINYCLOUD_BOOTSTRAP_HOST,
  'https://tee.node.tinycloud.xyz',
]);

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
