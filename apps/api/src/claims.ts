/**
 * Build email-related ID token claims when email scope is present.
 */
export function buildEmailClaims(
  user: { email: string; emailVerified: boolean },
  scopes: string[]
): Record<string, unknown> {
  const claims: Record<string, unknown> = {};
  if (scopes.includes('email')) {
    claims.email = user.email;
    claims.emailVerified = user.emailVerified;
  }
  return claims;
}
