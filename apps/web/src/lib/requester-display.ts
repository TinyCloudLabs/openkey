/**
 * Return the browser authority OpenKey can attribute to a widget request.
 * `URL.host` intentionally preserves a non-default port because SIWE domains
 * are authorities, not bare hostnames.
 */
export function originAuthority(origin: string): string | null {
  if (!origin || origin === '*') return null;
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

/**
 * Top-level requester copy may use only an origin-bound manifest name or the
 * browser authority. Caller-supplied presentation names remain visible in
 * Advanced details with their unverified provenance label.
 */
export function requesterDisplayName(
  verifiedManifestName: string | null,
  origin: string,
): string {
  return verifiedManifestName ?? originAuthority(origin) ?? 'Unknown origin';
}

/** Format an unsigned link's claimed authority without granting it an app identity. */
export function hostNamedByLink(domain: string | null | undefined): string {
  if (!domain || /[\s/@\\?#]/.test(domain)) return 'an unknown site';
  try {
    return new URL(`https://${domain}`).host.toLowerCase() || 'an unknown site';
  } catch {
    return 'an unknown site';
  }
}
