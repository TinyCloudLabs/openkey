// OAuth authorize endpoint - generates PKCE state and redirects to OpenKey
// This runs exactly once per request (unlike +page.server.ts load which can re-run)
import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { generateCodeVerifier, generateCodeChallenge, generateState } from '$lib/server/pkce';
import { env } from '$env/dynamic/private';

export const GET: RequestHandler = async ({ url, cookies }) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = generateState();

  cookies.set('oauth_code_verifier', codeVerifier, {
    path: '/',
    httpOnly: true,
    secure: url.protocol === 'https:',
    sameSite: 'lax',
    maxAge: 600,
  });

  cookies.set('oauth_state', state, {
    path: '/',
    httpOnly: true,
    secure: url.protocol === 'https:',
    sameSite: 'lax',
    maxAge: 600,
  });

  const clientId = env.ADMIN_OAUTH_CLIENT_ID;
  if (!clientId) {
    throw new Error('ADMIN_OAUTH_CLIENT_ID environment variable is not set');
  }

  const redirectUri = `${url.origin}/auth/callback`;
  const authorizeUrl = new URL(`${env.API_URL}/api/auth/oauth2/authorize`);
  authorizeUrl.searchParams.set('client_id', clientId);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', 'openid');
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('code_challenge', codeChallenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  throw redirect(302, authorizeUrl.toString());
};
