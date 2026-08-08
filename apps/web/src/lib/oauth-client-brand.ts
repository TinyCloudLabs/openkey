import { API_BASE } from './auth-client';

export type OAuthClientBrand = {
  name: string;
  uri: string | null;
  icon: string | null;
};

export class OAuthClientBrandLoadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OAuthClientBrandLoadError';
  }
}

type PublicClient = Record<string, unknown>;

function optionalString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

/** Convert Better Auth's public client fields to the presentation fields we render. */
export function normalizeOAuthClientBrand(value: unknown): OAuthClientBrand | null {
  if (!value || typeof value !== 'object') return null;
  const client = value as PublicClient;
  if (client.disabled === true) return null;

  const name = optionalString(client.client_name) ?? optionalString(client.name);
  if (!name) return null;

  return {
    name,
    uri: optionalString(client.client_uri) ?? optionalString(client.uri),
    icon: optionalString(client.logo_uri) ?? optionalString(client.icon),
  };
}

function responseBrand(value: unknown): OAuthClientBrand | null {
  const direct = normalizeOAuthClientBrand(value);
  if (direct) return direct;
  if (!value || typeof value !== 'object') return null;
  return normalizeOAuthClientBrand((value as PublicClient).client);
}

async function responseError(response: Response): Promise<OAuthClientBrandLoadError> {
  let message: string | null = null;
  try {
    const body = await response.json();
    if (body && typeof body === 'object' && typeof (body as PublicClient).message === 'string') {
      message = (body as PublicClient).message;
    }
  } catch {
    // Fall back to the status below when the error response is not JSON.
  }
  return new OAuthClientBrandLoadError(message || `Failed to load application (${response.status})`);
}

export async function loadOAuthClientBrand(clientId: string): Promise<OAuthClientBrand | null> {
  if (!clientId) return null;
  try {
    const response = await fetch(
      `${API_BASE}/api/auth/oauth2/public-client?client_id=${encodeURIComponent(clientId)}`,
      { credentials: 'include' },
    );
    if (!response.ok) throw await responseError(response);
    return responseBrand(await response.json());
  } catch {
    return null;
  }
}

/**
 * Better Auth verifies the signed OAuth envelope before disclosing a client to a
 * signed-out visitor. This is deliberately not a client-id lookup endpoint.
 */
export async function loadPreloginOAuthClientBrand(
  oauthQuery: string | undefined,
): Promise<OAuthClientBrand | null> {
  if (!oauthQuery) return null;
  const clientId = new URLSearchParams(oauthQuery).get('client_id');
  if (!clientId) return null;
  try {
    const response = await fetch(`${API_BASE}/api/auth/oauth2/public-client-prelogin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId, oauth_query: oauthQuery }),
    });
    return response.ok ? responseBrand(await response.json()) : null;
  } catch {
    return null;
  }
}
