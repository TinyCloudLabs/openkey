// Passkey proxy routes for iframe embed mode
// Proxies better-auth passkey endpoints, replacing cookie-based challenge
// storage with token-based storage to work in third-party iframe contexts
// where SameSite=Lax cookies are blocked.
import { Hono } from 'hono';
import { auth } from '../auth';

// In-memory challenge store: maps challengeToken -> cookie name+value
const challengeStore = new Map<string, { cookieName: string; cookieValue: string; expires: number }>();

function cleanExpiredChallenges() {
  const now = Date.now();
  for (const [token, entry] of challengeStore) {
    if (entry.expires <= now) {
      challengeStore.delete(token);
    }
  }
}

// Base URL for constructing internal requests to better-auth
const baseURL = process.env.BETTER_AUTH_URL!;

/**
 * Extract the passkey challenge cookie name and value from Set-Cookie headers.
 * Cookie name is `better-auth.better-auth-passkey` (with prefix),
 * or `__Secure-better-auth.better-auth-passkey` in production.
 */
function extractPasskeyCookie(headers: Headers): { name: string; value: string } | null {
  const setCookies = headers.getSetCookie();
  for (const cookie of setCookies) {
    if (cookie.includes('better-auth-passkey')) {
      // Match the full cookie name (including any prefix) and value
      const match = cookie.match(/^([^=]*better-auth-passkey)=([^;]+)/);
      if (match) return { name: match[1]!, value: match[2]! };
    }
  }
  return null;
}

/**
 * Extract the session token from the response.
 * Checks the bearer plugin's `set-auth-token` header first,
 * then falls back to parsing Set-Cookie headers.
 */
function extractSessionToken(headers: Headers): string | null {
  // Bearer plugin returns token via this header
  const bearerToken = headers.get('set-auth-token');
  if (bearerToken) return bearerToken;

  // Fallback: parse Set-Cookie headers
  const setCookies = headers.getSetCookie();
  for (const cookie of setCookies) {
    if (cookie.includes('better-auth.session_token')) {
      const match = cookie.match(/(?:__Secure-)?better-auth\.session_token=([^;]+)/);
      if (match) return match[1]!;
    }
  }
  return null;
}

export const passkeyProxyRouter = new Hono();

// POST /generate-register-options
// Proxies to GET /api/auth/passkey/generate-register-options
passkeyProxyRouter.post('/generate-register-options', async (c) => {
  cleanExpiredChallenges();

  type GenerateRegisterOptionsBody = { authenticatorAttachment?: string; name?: string };
  const body = await c.req.json<GenerateRegisterOptionsBody>().catch((): GenerateRegisterOptionsBody => ({}));

  // Build query params from body
  const params = new URLSearchParams();
  if (body.authenticatorAttachment) params.set('authenticatorAttachment', body.authenticatorAttachment);
  if (body.name) params.set('name', body.name);

  const url = `${baseURL}/api/auth/passkey/generate-register-options${params.toString() ? '?' + params.toString() : ''}`;

  // Forward the request to better-auth (pass cookies/auth headers from original request)
  const internalReq = new Request(url, {
    method: 'GET',
    headers: c.req.raw.headers,
  });

  const response = await auth.handler(internalReq);

  // Extract the passkey challenge cookie
  const passkeyCookie = extractPasskeyCookie(response.headers);
  if (!passkeyCookie) {
    // Pass through the response as-is if no cookie (e.g. error response)
    const responseBody = await response.json();
    return c.json(responseBody, response.status as any);
  }

  // Generate a challenge token and store the cookie name+value
  const challengeToken = crypto.randomUUID();
  challengeStore.set(challengeToken, {
    cookieName: passkeyCookie.name,
    cookieValue: passkeyCookie.value,
    expires: Date.now() + 5 * 60 * 1000, // 5 minutes
  });

  // Return original JSON body + challengeToken (without Set-Cookie)
  const responseBody = await response.json();
  return c.json({ ...responseBody, challengeToken });
});

// POST /verify-registration
// Proxies to POST /api/auth/passkey/verify-registration
passkeyProxyRouter.post('/verify-registration', async (c) => {
  const body = await c.req.json();
  const { challengeToken, ...passkeyBody } = body;

  if (!challengeToken) {
    return c.json({ error: 'challengeToken is required' }, 400);
  }

  // Look up and consume the stored cookie
  const stored = challengeStore.get(challengeToken);
  if (!stored) {
    return c.json({ error: 'Challenge token not found or expired' }, 400);
  }
  challengeStore.delete(challengeToken);

  if (stored.expires <= Date.now()) {
    return c.json({ error: 'Challenge token expired' }, 400);
  }

  // Build cookie header with the stored passkey challenge (using correct cookie name)
  const existingCookies = c.req.header('cookie') || '';
  const cookieHeader = existingCookies
    ? `${existingCookies}; ${stored.cookieName}=${stored.cookieValue}`
    : `${stored.cookieName}=${stored.cookieValue}`;

  const headers = new Headers(c.req.raw.headers);
  headers.set('cookie', cookieHeader);

  const internalReq = new Request(`${baseURL}/api/auth/passkey/verify-registration`, {
    method: 'POST',
    headers,
    body: JSON.stringify(passkeyBody),
  });

  const response = await auth.handler(internalReq);
  const responseBody = await response.json();

  // Extract session token from response cookies
  const sessionToken = extractSessionToken(response.headers);

  if (sessionToken) {
    return c.json({ ...responseBody, sessionToken });
  }

  return c.json(responseBody, response.status as any);
});

// POST /generate-authenticate-options
// Proxies to GET /api/auth/passkey/generate-authenticate-options
passkeyProxyRouter.post('/generate-authenticate-options', async (c) => {
  cleanExpiredChallenges();

  const url = `${baseURL}/api/auth/passkey/generate-authenticate-options`;

  const internalReq = new Request(url, {
    method: 'GET',
    headers: c.req.raw.headers,
  });

  const response = await auth.handler(internalReq);

  // Extract the passkey challenge cookie
  const passkeyCookie = extractPasskeyCookie(response.headers);
  if (!passkeyCookie) {
    const responseBody = await response.json();
    return c.json(responseBody, response.status as any);
  }

  // Generate a challenge token and store the cookie name+value
  const challengeToken = crypto.randomUUID();
  challengeStore.set(challengeToken, {
    cookieName: passkeyCookie.name,
    cookieValue: passkeyCookie.value,
    expires: Date.now() + 5 * 60 * 1000,
  });

  const responseBody = await response.json();
  return c.json({ ...responseBody, challengeToken });
});

// POST /verify-authentication
// Proxies to POST /api/auth/passkey/verify-authentication
passkeyProxyRouter.post('/verify-authentication', async (c) => {
  const body = await c.req.json();
  const { challengeToken, ...passkeyBody } = body;

  if (!challengeToken) {
    return c.json({ error: 'challengeToken is required' }, 400);
  }

  // Look up and consume the stored cookie
  const stored = challengeStore.get(challengeToken);
  if (!stored) {
    return c.json({ error: 'Challenge token not found or expired' }, 400);
  }
  challengeStore.delete(challengeToken);

  if (stored.expires <= Date.now()) {
    return c.json({ error: 'Challenge token expired' }, 400);
  }

  // Build cookie header with the stored passkey challenge (using correct cookie name)
  const existingCookies = c.req.header('cookie') || '';
  const cookieHeader = existingCookies
    ? `${existingCookies}; ${stored.cookieName}=${stored.cookieValue}`
    : `${stored.cookieName}=${stored.cookieValue}`;

  const headers = new Headers(c.req.raw.headers);
  headers.set('cookie', cookieHeader);

  const internalReq = new Request(`${baseURL}/api/auth/passkey/verify-authentication`, {
    method: 'POST',
    headers,
    body: JSON.stringify(passkeyBody),
  });

  const response = await auth.handler(internalReq);
  const responseBody = await response.json();

  // Extract session token from response cookies
  const sessionToken = extractSessionToken(response.headers);

  if (sessionToken) {
    return c.json({ ...responseBody, sessionToken });
  }

  return c.json(responseBody, response.status as any);
});
