import { cors } from 'hono/cors';
import type { MiddlewareHandler } from 'hono';

export const OPENKEY_SESSION_PROOF_HEADER = 'OpenKey-Session-Proof';

/** Endpoint paths relative to the issuer (`BETTER_AUTH_URL` + `/api/auth`). */
export const NATIVE_DELEGATION_ENDPOINT_PATHS = {
  par: '/oauth2/par',
  renew: '/oauth2/tinycloud/renew',
  revoke: '/oauth2/tinycloud/revoke',
} as const;

/**
 * Discovery and the public protocol endpoints a native app calls without
 * cookies (TC-773 §1.1). Matched exactly against the WHATWG-normalized
 * pathname, the same pathname better-auth routes on. The cookie-authenticated
 * consent routes (`/api/auth/oauth2/consent`, `/api/oauth/tinycloud/...`) and
 * every account route stay under the restricted, credentialed CORS policy.
 */
const PUBLIC_PROTOCOL_PATHS: ReadonlySet<string> = new Set([
  '/.well-known/oauth-authorization-server',
  '/.well-known/oauth-authorization-server/api/auth',
  '/.well-known/openid-configuration',
  '/api/auth/.well-known/openid-configuration',
  '/api/auth/oauth2/token',
  `/api/auth${NATIVE_DELEGATION_ENDPOINT_PATHS.par}`,
  `/api/auth${NATIVE_DELEGATION_ENDPOINT_PATHS.renew}`,
  `/api/auth${NATIVE_DELEGATION_ENDPOINT_PATHS.revoke}`,
]);

export function isPublicProtocolPath(url: string): boolean {
  return PUBLIC_PROTOCOL_PATHS.has(new URL(url).pathname);
}

const publicProtocolCors = cors({
  origin: '*',
  credentials: false,
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', OPENKEY_SESSION_PROOF_HEADER],
});

/**
 * One CORS decision per request: credential-free `*` for the public protocol
 * paths, otherwise the caller's restricted policy. A single predicate keeps
 * the two sets disjoint.
 */
export function protocolAwareCors(restricted: MiddlewareHandler): MiddlewareHandler {
  return (c, next) => (isPublicProtocolPath(c.req.url) ? publicProtocolCors(c, next) : restricted(c, next));
}

export function nativeDelegationMetadata(issuer: string) {
  return {
    pushed_authorization_request_endpoint: `${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS.par}`,
    tinycloud_delegation_renew_endpoint: `${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS.renew}`,
    tinycloud_delegation_revocation_endpoint: `${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS.revoke}`,
  };
}

/** Adds the native delegation endpoints to a provider metadata response. */
export async function withNativeDelegationMetadata(response: Response, issuer: string): Promise<Response> {
  if (!response.ok) return response;
  const metadata = await response.json() as Record<string, unknown>;
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  return Response.json({ ...metadata, ...nativeDelegationMetadata(issuer) }, { status: response.status, headers });
}
