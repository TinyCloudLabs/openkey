// OAuth callback handler - exchanges authorization code for tokens
import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { env } from '$env/dynamic/private';

export const GET: RequestHandler = async ({ url, cookies }) => {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error) {
    const description = url.searchParams.get('error_description') || error;
    console.error('[OAuth callback] Error:', description);
    throw redirect(302, `/login?error=${encodeURIComponent(description)}`);
  }

  if (!code || !state) {
    throw redirect(302, '/login?error=missing_params');
  }

  // Verify state matches what we stored
  const storedState = cookies.get('oauth_state');
  if (!storedState || storedState !== state) {
    // Clear stale cookies
    cookies.delete('oauth_state', { path: '/' });
    cookies.delete('oauth_code_verifier', { path: '/' });
    throw redirect(302, '/login?error=state_mismatch');
  }

  // Retrieve code_verifier
  const codeVerifier = cookies.get('oauth_code_verifier');
  if (!codeVerifier) {
    cookies.delete('oauth_state', { path: '/' });
    throw redirect(302, '/login?error=missing_verifier');
  }

  // Clean up PKCE cookies
  cookies.delete('oauth_state', { path: '/' });
  cookies.delete('oauth_code_verifier', { path: '/' });

  // Exchange authorization code for tokens (public client — PKCE only, no secret)
  const redirectUri = `${url.origin}/auth/callback`;

  const tokenResponse = await fetch(`${env.API_URL}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: env.ADMIN_OAUTH_CLIENT_ID || '',
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenResponse.ok) {
    const errorData = await tokenResponse.json().catch(() => ({}));
    const errorMsg = errorData.error_description || errorData.error || 'token_exchange_failed';
    console.error('[OAuth callback] Token exchange failed:', errorMsg);
    throw redirect(302, `/login?error=${encodeURIComponent(errorMsg)}`);
  }

  const tokens = await tokenResponse.json();

  // Store access_token in an httpOnly session cookie
  cookies.set('admin_session', tokens.access_token, {
    path: '/',
    httpOnly: true,
    secure: url.protocol === 'https:',
    sameSite: 'lax',
    maxAge: tokens.expires_in || 3600,
  });

  // Store refresh_token if provided (longer-lived)
  if (tokens.refresh_token) {
    cookies.set('admin_refresh_token', tokens.refresh_token, {
      path: '/',
      httpOnly: true,
      secure: url.protocol === 'https:',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 7, // 7 days
    });
  }

  throw redirect(302, '/');
};
