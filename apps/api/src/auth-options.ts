/**
 * The API issues session cookies while the browser may be on either OpenKey
 * surface. Keep this isolated so the production cookie policy is testable
 * without constructing the database- and TEE-backed auth service.
 */
export function crossSubDomainCookieOptions(isDevelopment: boolean) {
  return isDevelopment
    ? { enabled: false }
    : { enabled: true, domain: '.openkey.so' };
}
