import { API_BASE } from './auth-client';
import { startAuthentication } from '@simplewebauthn/browser';

export async function orgAdminRequest<T>(path: string, body?: unknown, token?: string): Promise<T> {
  const response = await fetch(`${API_BASE}/api${path}`, {
    credentials: 'include', method: body === undefined ? 'GET' : 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { 'x-invitation-token': token } : {}) }, body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const result = await response.json().catch(() => null);
    throw Object.assign(new Error(String(response.status)), { code: result?.code });
  }
  return response.json();
}
export async function orgAdminAction<T>(challengePath: string, actionPath: string, body: Record<string, unknown> = {}): Promise<T> {
  if (window.top !== window.self) throw new Error('403');
  const { challenge } = await orgAdminRequest<{ challenge: { nonce: string; challenge: string; allowCredentials: { id: string; type: 'public-key' }[] } }>(challengePath, body);
  const assertion = await startAuthentication({ optionsJSON: {
    challenge: challenge.challenge, rpId: location.hostname, userVerification: 'required', allowCredentials: challenge.allowCredentials,
  } });
  return orgAdminRequest<T>(actionPath, { ...body, nonce: challenge.nonce, assertion });
}
