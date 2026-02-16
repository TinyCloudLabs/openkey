// PKCE utilities for server-side OAuth flow
import { randomBytes, createHash } from 'node:crypto';

/** Generate a cryptographically random code_verifier (43-128 chars, base64url) */
export function generateCodeVerifier(): string {
  return randomBytes(32).toString('base64url');
}

/** Generate code_challenge = base64url(sha256(verifier)) */
export function generateCodeChallenge(verifier: string): string {
  const hash = createHash('sha256').update(verifier).digest();
  return hash.toString('base64url');
}

/** Generate a random state parameter for CSRF protection */
export function generateState(): string {
  return randomBytes(16).toString('base64url');
}
