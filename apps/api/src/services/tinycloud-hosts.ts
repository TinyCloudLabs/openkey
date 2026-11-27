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

/** Native grants retain exact hosts except for the two production node names. */
export function sameTinyCloudHost(left: string, right: string): boolean {
  return left === right || (TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(left) && TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(right));
}

// TC-3657: canonical node DID paired with the configured bootstrap host. Used only by
// `/authorize-tinycloud-setup` to fill the location record's `nodes[]` entry — never by
// renewal-lease (which has its own pin at `renewal-lease.ts`, different trust purpose).
// MUST be set in production before the endpoint is exposed; the route fails closed
// without it (fail-closed; the server never signs a record pointing at an unverified node). Must be a canonical Ed25519
// `did:key:z...` matching the trusted bootstrap host's `/info` response.
const TINYCLOUD_DEFAULT_NODE_DID_PATTERN = /^did:key:z[1-9A-HJ-NP-Za-km-z]{40,}$/;

/** The configured trusted node DID, if any. Reads `TINYCLOUD_DEFAULT_NODE_DID`. Returns
 *  `null` when unset or malformed; the setup endpoint treats `null` as fail-closed. */
export function trustedTinyCloudBootstrapNodeDid(): string | null {
  const raw = process.env.TINYCLOUD_DEFAULT_NODE_DID;
  if (typeof raw !== 'string') return null;
  return TINYCLOUD_DEFAULT_NODE_DID_PATTERN.test(raw) ? raw : null;
}

export interface TinyCloudBootstrapNode {
  readonly nodeDid: string;
  readonly origin: string;
}

/** The node DID + origin pair for the TC-3657 setup record. Both components come from
 *  env/validated allowlist; neither can be influenced by the caller. Returns `null` when
 *  either side is missing (fail-closed — the server never signs a record
 *  pointing at an unverified node). */
export function defaultTinyCloudBootstrapNode(configuredHost: string = DEFAULT_TINYCLOUD_BOOTSTRAP_HOST): TinyCloudBootstrapNode | null {
  const nodeDid = trustedTinyCloudBootstrapNodeDid();
  if (!nodeDid) return null;
  const origin = canonicalTrustedTinyCloudHost(configuredHost, configuredHost);
  if (!origin) return null;
  return { nodeDid, origin };
}
