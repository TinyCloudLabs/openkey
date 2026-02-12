// Server-side auth helper - validates OAuth access tokens
const API_URL = process.env.API_URL || 'http://localhost:3001';

interface AuthUser {
  id: string;
  email: string;
  name?: string | null;
}

interface ValidateTokenResponse {
  user: AuthUser;
}

/**
 * Validate an OAuth access token by calling the API's userinfo endpoint.
 * Returns the user if valid, null otherwise.
 */
export async function validateToken(
  accessToken: string | undefined
): Promise<ValidateTokenResponse | null> {
  if (!accessToken) {
    return null;
  }

  const response = await fetch(`${API_URL}/api/auth/oauth2/userinfo`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    return null;
  }

  const data = await response.json();

  if (!data || !data.sub) {
    return null;
  }

  return {
    user: {
      id: data.sub,
      email: data.email,
      name: data.name ?? null,
    },
  };
}
