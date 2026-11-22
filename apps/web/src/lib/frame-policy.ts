// Which OpenKey pages may be shown inside another page's frame. The login page opens in its own window; a page that
// frames it could lay its own elements over its buttons, so it refuses every parent. The sign pages and every other
// page are not listed and keep their headers.

const UNFRAMEABLE_PATHS: Record<string, true> = { '/auth/login': true };

/** The `Content-Security-Policy` value that forbids framing for this path, or null when the page's headers are left as they are. */
export function framePolicyFor(pathname: string): string | null {
  const path = pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
  return Object.hasOwn(UNFRAMEABLE_PATHS, path) ? "frame-ancestors 'none'" : null;
}

/**
 * The response with the frame policy added for the pages above. The policy joins any `Content-Security-Policy` the
 * response already has; a response's own headers can be read-only, so the result is a new response.
 */
export function withFramePolicy(response: Response, pathname: string): Response {
  const policy = framePolicyFor(pathname);
  if (policy === null) return response;
  const headers = new Headers(response.headers);
  headers.append('content-security-policy', policy);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
