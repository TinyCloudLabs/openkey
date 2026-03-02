import { loadCredentials, saveCredentials, isTokenExpired } from './credentials';
import { refreshAccessToken, OpenKeyError } from '@openkey/core';
import type { AuthTokens } from '@openkey/core';

export async function getValidTokens(host: string, clientId: string): Promise<AuthTokens> {
  const creds = loadCredentials(host);
  if (!creds) {
    throw new OpenKeyError('UNAUTHORIZED', 'Not logged in. Run `openkey login` first.');
  }

  if (!isTokenExpired(creds)) {
    return creds.tokens;
  }

  if (creds.tokens.refreshToken) {
    const tokens = await refreshAccessToken({
      host,
      refreshToken: creds.tokens.refreshToken,
      clientId,
    });
    saveCredentials(host, clientId, tokens);
    return tokens;
  }

  throw new OpenKeyError('UNAUTHORIZED', 'Session expired. Run `openkey login` again.');
}

export async function authenticatedFetch(
  host: string,
  clientId: string,
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const tokens = await getValidTokens(host, clientId);
  return fetch(`${host}${path}`, {
    ...init,
    headers: {
      ...init?.headers,
      Authorization: `Bearer ${tokens.accessToken}`,
    },
  });
}
