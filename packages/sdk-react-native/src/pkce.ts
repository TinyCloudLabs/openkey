/**
 * PKCE (Proof Key for Code Exchange) utilities for React Native.
 *
 * Unlike the browser SDK, this module avoids `btoa()` which is not
 * available in all React Native runtimes (e.g. Hermes < 0.73).
 * Base64url encoding is implemented from scratch using a lookup table.
 *
 * The default SHA-256 implementation uses `crypto.subtle.digest` which
 * is available in Hermes 0.73+. For older runtimes, pass a custom
 * `SHA256Fn` backed by expo-crypto or react-native-quick-crypto.
 */

/**
 * A function that computes the SHA-256 hash of the input string.
 * Return the raw 32-byte digest as a Uint8Array.
 */
export type SHA256Fn = (input: string) => Promise<Uint8Array>;

// Standard base64 alphabet lookup table
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Pure JS base64url encoding from a Uint8Array.
 * Does NOT use `btoa()` — safe for all React Native runtimes.
 */
export function base64UrlEncode(buffer: Uint8Array): string {
  let base64 = '';
  const len = buffer.length;

  for (let i = 0; i < len; i += 3) {
    const b0 = buffer[i]!;
    const b1 = i + 1 < len ? buffer[i + 1]! : 0;
    const b2 = i + 2 < len ? buffer[i + 2]! : 0;

    const triplet = (b0 << 16) | (b1 << 8) | b2;

    base64 += BASE64_CHARS[(triplet >> 18) & 0x3f];
    base64 += BASE64_CHARS[(triplet >> 12) & 0x3f];
    base64 += i + 1 < len ? BASE64_CHARS[(triplet >> 6) & 0x3f] : '';
    base64 += i + 2 < len ? BASE64_CHARS[triplet & 0x3f] : '';
  }

  // Convert base64 to base64url: replace + with -, / with _, strip = padding
  return base64.replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Generate a cryptographically random code verifier for PKCE.
 * Returns a 43-character base64url string (32 random bytes).
 */
export function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Default SHA-256 implementation using Web Crypto API.
 * Available in Hermes 0.73+ and modern JS runtimes.
 */
async function defaultSha256(input: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

/**
 * Generate the PKCE code challenge from a code verifier.
 *
 * @param verifier - The code verifier string
 * @param sha256 - Optional custom SHA-256 function (for expo-crypto, react-native-quick-crypto, etc.)
 * @returns Base64url-encoded SHA-256 hash of the verifier
 */
export async function generateCodeChallenge(
  verifier: string,
  sha256?: SHA256Fn,
): Promise<string> {
  const hashFn = sha256 ?? defaultSha256;
  const digest = await hashFn(verifier);
  return base64UrlEncode(digest);
}

/**
 * Generate a cryptographically random state parameter.
 * Returns a 22-character base64url string (16 random bytes).
 */
export function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}
