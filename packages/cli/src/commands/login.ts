import { login } from '../auth';
import { saveCredentials, loadCredentials, isTokenExpired } from '../credentials';
import { refreshAccessToken } from '@openkey/core';

export async function loginCommand(options: { host: string; clientId: string; noBrowser: boolean }) {
  const existing = loadCredentials(options.host);

  if (existing && !isTokenExpired(existing)) {
    console.log('Already logged in.');
    return;
  }

  // Try refresh if we have a refresh token
  if (existing?.tokens.refreshToken) {
    try {
      console.log('Refreshing session...');
      const tokens = await refreshAccessToken({
        host: options.host,
        refreshToken: existing.tokens.refreshToken,
        clientId: options.clientId,
      });
      saveCredentials(options.host, options.clientId, tokens);
      console.log('Session refreshed.');
      return;
    } catch {
      // Refresh failed, proceed to full login
    }
  }

  const tokens = await login(options);
  saveCredentials(options.host, options.clientId, tokens);
  console.log('\nLogged in successfully.');
}
