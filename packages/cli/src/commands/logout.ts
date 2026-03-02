import { loadCredentials, clearCredentials } from '../credentials';

export async function logoutCommand(options: { host: string }) {
  const creds = loadCredentials(options.host);
  if (!creds) {
    console.log('Not logged in.');
    return;
  }

  // Try to revoke the token on the server
  try {
    await fetch(`${options.host}/api/auth/revoke`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${creds.tokens.accessToken}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ token: creds.tokens.accessToken }),
    });
  } catch {
    // Server revocation failed, clear local credentials anyway
  }

  clearCredentials(options.host);
  console.log('Logged out.');
}
