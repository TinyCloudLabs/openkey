import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { generateCodeVerifier, generateCodeChallenge, generateState } from '$lib/server/pkce';
import { env } from '$env/dynamic/private';

export const load: PageServerLoad = async ({ url, cookies }) => {
  // Generate PKCE values
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = generateState();

  // Store code_verifier and state in httpOnly cookies for the callback
  cookies.set('oauth_code_verifier', codeVerifier, {
    path: '/',
    httpOnly: true,
    secure: url.protocol === 'https:',
    sameSite: 'lax',
    maxAge: 600, // 10 minutes
  });

  cookies.set('oauth_state', state, {
    path: '/',
    httpOnly: true,
    secure: url.protocol === 'https:',
    sameSite: 'lax',
    maxAge: 600,
  });

  // Build the authorization URL
  const redirectUri = `${url.origin}/auth/callback`;
  const authorizeUrl = new URL(`${env.API_URL}/api/auth/oauth2/authorize`);
  const clientId = env.ADMIN_OAUTH_CLIENT_ID;
  if (!clientId) {
    throw new Error('ADMIN_OAUTH_CLIENT_ID environment variable is not set');
  }

  authorizeUrl.searchParams.set('client_id', clientId);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', 'openid');
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('code_challenge', codeChallenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  return {
    authorizeUrl: authorizeUrl.toString(),
  };
};
