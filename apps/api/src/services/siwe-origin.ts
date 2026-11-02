// SIWE origin guard (TC-1486).
//
// OpenKey signs caller-supplied message bytes. A hostile site could otherwise
// get a user to sign an EIP-4361 (SIWE) message that claims ANOTHER relying
// party's domain and replay it there. The only party that knows who is really
// asking is the wallet: the requesting origin is the postMessage sender the
// widget verified. So a SIWE-shaped message is signable only when its `domain`
// (and its `URI`, when that is a web URL) names exactly that origin. There is
// no user override and an unattributed origin is refused.
//
// THIS FILE IS DEPENDENCY-FREE ON PURPOSE. The API runtime image ships only
// `apps/api/src`, so `apps/api/src/services/siwe-origin.ts` carries a
// byte-identical copy; `apps/api/src/__tests__/siwe-origin-parity.test.ts`
// fails if the two drift. Edit both together.

export type SiweOriginRefusalCode =
  | 'unattributed-origin'
  | 'invalid-origin'
  | 'incomplete-siwe'
  | 'domain-mismatch'
  | 'uri-mismatch';

export type SiweOriginCheck =
  | { siwe: false }
  | { siwe: true; ok: true }
  | { siwe: true; ok: false; code: SiweOriginRefusalCode; message: string };

// Matches across any whitespace (including newlines) so a header split over
// lines is still DETECTED; extraction below is per line and strict.
const HEADER_ANYWHERE = /wants\s+you\s+to\s+sign\s+in\s+with\s+your\s+ethereum\s+account\s*:/i;
const HEADER_IN_LINE = /wants\s+you\s+to\s+sign\s+in\s+with\s+your\s+ethereum\s+account\s*:/i;
const URI_LINE = /^\s*uri\s*:(.*)$/i;
const NONCE_LINE = /^\s*nonce\s*:/i;
// Every line terminator a lenient parser might honour.
const LINE_BREAK = /\r\n|[\n\r\u000b\u000c\u0085\u2028\u2029]/;
// Printable ASCII without whitespace: anything else in a URI value is refused.
const PLAIN_URI_VALUE = /^[\x21-\x7e]+$/;
// `@tinycloud/web-sdk` defaults the SIWE domain to `location.hostname`, which
// drops the port, so every local dev server (`localhost:5173`) would be
// refused. Loopback hosts are the one place a bare hostname is accepted for a
// ported origin: nothing remote can be impersonated by a loopback page.
const LOOPBACK_HOSTNAMES: Record<string, true | undefined> = { localhost: true, '127.0.0.1': true, '[::1]': true };

// Exo's macOS app (Tauri) serves its bundled UI at this fixed custom-scheme
// origin. URL parsing gives a custom scheme an opaque `null` origin, so it can
// never pass canonicalOrigin; it is matched byte-exactly instead and checked as
// the loopback host it serves. A message it gets signed must name the domain
// `localhost` and a `did:`/`ucan:` URI, so it cannot claim a public site.
// (Windows Tauri is `http://tauri.localhost`, which already passes.)
type ExpectedOrigin = Pick<URL, 'origin' | 'host' | 'hostname' | 'port'>;
const APP_SHELL_ORIGINS: Record<string, ExpectedOrigin | undefined> = {
  'tauri://localhost': { origin: 'tauri://localhost', host: 'localhost', hostname: 'localhost', port: '' },
};

function refusal(code: SiweOriginRefusalCode, message: string): SiweOriginCheck {
  return { siwe: true, ok: false, code, message };
}

/** Does the text look like an EIP-4361 message (header, or URI: plus Nonce: lines)? */
export function isSiweShaped(text: string): boolean {
  if (HEADER_ANYWHERE.test(text)) return true;
  const lines = text.split(LINE_BREAK);
  return lines.some((l) => URI_LINE.test(l)) && lines.some((l) => NONCE_LINE.test(l));
}

/**
 * Parse a requesting origin into its canonical form. Only an exact
 * `scheme://host[:port]` serialization (case aside) is accepted: no userinfo,
 * path, query, fragment, whitespace, or default-port spelling.
 */
function canonicalOrigin(origin: string): URL | null {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password) return null;
  if (url.origin !== origin.toLowerCase()) return null;
  return url;
}

/**
 * Check one message against the verified requesting origin.
 * Non-SIWE text returns `{ siwe: false }` and is never touched.
 */
export function checkSiweOrigin(text: string, requestOrigin: string | null | undefined): SiweOriginCheck {
  if (!isSiweShaped(text)) return { siwe: false };

  if (typeof requestOrigin !== 'string' || requestOrigin === '' || requestOrigin === '*' || requestOrigin === 'null') {
    return refusal(
      'unattributed-origin',
      'OpenKey cannot tell which site is asking, so it will not sign a sign-in (SIWE) message.',
    );
  }
  const expected: ExpectedOrigin | null = Object.hasOwn(APP_SHELL_ORIGINS, requestOrigin)
    ? APP_SHELL_ORIGINS[requestOrigin]!
    : canonicalOrigin(requestOrigin);
  if (!expected) {
    return refusal(
      'invalid-origin',
      'OpenKey could not verify the requesting site, so it will not sign a sign-in (SIWE) message.',
    );
  }

  const lines = text.split(LINE_BREAK);
  const domains: string[] = [];
  for (const line of lines) {
    const at = line.search(HEADER_IN_LINE);
    if (at < 0) continue;
    const prefix = line.slice(0, at);
    // The ABNF is `<domain> SP "wants you…"`. Keep everything else (leading
    // whitespace, userinfo, trailing dot) so it fails the equality below.
    domains.push(prefix.endsWith(' ') ? prefix.slice(0, -1) : prefix);
  }
  const uris: string[] = [];
  for (const line of lines) {
    const m = URI_LINE.exec(line);
    if (m) uris.push(m[1]!);
  }
  if (domains.length === 0 || uris.length === 0) {
    return refusal(
      'incomplete-siwe',
      'This looks like a sign-in (SIWE) message but its domain or URI could not be read, so it will not be signed.',
    );
  }

  const loopbackHostname = Object.hasOwn(LOOPBACK_HOSTNAMES, expected.hostname) && expected.port ? expected.hostname : null;
  for (const domain of domains) {
    const normalized = domain.toLowerCase();
    if (normalized !== expected.host && normalized !== loopbackHostname) {
      return refusal(
        'domain-mismatch',
        `This sign-in message claims to be for a different site than the one asking (${expected.origin}), so it will not be signed.`,
      );
    }
  }

  for (const raw of uris) {
    const value = raw.startsWith(' ') ? raw.slice(1) : raw;
    if (!PLAIN_URI_VALUE.test(value) || value.includes('\\')) {
      return refusal('uri-mismatch', 'This sign-in message has a malformed URI, so it will not be signed.');
    }
    let uri: URL;
    try {
      uri = new URL(value);
    } catch {
      return refusal('uri-mismatch', 'This sign-in message has a malformed URI, so it will not be signed.');
    }
    // A `did:` or `ucan:` URI names the delegated session key or the revoked
    // UCAN (TinyCloud delegation / owner-revocation SIWE). It carries no web
    // origin, so it cannot impersonate another site; the domain check above
    // is what binds the message to the origin.
    if (uri.protocol === 'did:' || uri.protocol === 'ucan:') continue;
    if (
      (uri.protocol !== 'https:' && uri.protocol !== 'http:') ||
      uri.username ||
      uri.password ||
      uri.origin !== expected.origin
    ) {
      return refusal(
        'uri-mismatch',
        `This sign-in message points at a different site than the one asking (${expected.origin}), so it will not be signed.`,
      );
    }
  }

  return { siwe: true, ok: true };
}

/** Decode `0x…` hex as UTF-8 text, or null when it is not hex text. */
export function decodeHexUtf8(value: string): string | null {
  if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(value)) return null;
  const bytes = new Uint8Array((value.length - 2) / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(value.slice(2 + i * 2, 4 + i * 2), 16);
  return new TextDecoder().decode(bytes);
}

/**
 * Check a message as it will reach the signer. A `0x…` hex string is checked
 * both as written and as the UTF-8 bytes a wallet RPC or `raw` signature would
 * actually cover, so SIWE text cannot hide inside hex.
 */
export function checkSignableMessage(message: string, requestOrigin: string | null | undefined): SiweOriginCheck {
  const direct = checkSiweOrigin(message, requestOrigin);
  if (direct.siwe && !direct.ok) return direct;
  const decoded = decodeHexUtf8(message);
  if (decoded !== null) {
    const hidden = checkSiweOrigin(decoded, requestOrigin);
    if (hidden.siwe) return hidden;
  }
  return direct;
}
