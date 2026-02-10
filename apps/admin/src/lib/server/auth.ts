// Server-side auth helper - validates sessions by calling the main API
const API_URL = process.env.API_URL || 'http://localhost:3001';

interface AuthUser {
  id: string;
  email: string;
  name?: string | null;
}

interface AuthSession {
  id: string;
  token: string;
}

interface GetSessionResponse {
  user: AuthUser;
  session: AuthSession;
}

/**
 * Validate a session by forwarding cookies to the main API's get-session endpoint.
 * Returns the user and session if valid, null otherwise.
 */
export async function validateSession(
  cookieHeader: string | null
): Promise<GetSessionResponse | null> {
  if (!cookieHeader) {
    return null;
  }

  const response = await fetch(`${API_URL}/api/auth/get-session`, {
    headers: {
      cookie: cookieHeader,
    },
  });

  if (!response.ok) {
    return null;
  }

  const data = await response.json();

  // better-auth returns null/empty if no valid session
  if (!data || !data.user) {
    return null;
  }

  return {
    user: {
      id: data.user.id,
      email: data.user.email,
      name: data.user.name ?? null,
    },
    session: {
      id: data.session.id,
      token: data.session.token,
    },
  };
}
