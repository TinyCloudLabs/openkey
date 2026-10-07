import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';

import { createProviderInterceptors, type ProviderInterceptorDatabase } from '../services/native-delegation/interceptors';

// Every lookup misses: the token is unknown to OpenKey and the client is not
// native-capable, so revoke goes to the provider with the hint forced.
const emptyDatabase = {
  oauthClient: { findMany: async () => [], findUnique: async () => null },
  oauthRefreshToken: { findUnique: async () => null },
  oauthAccessToken: { findUnique: async () => null },
  tinyCloudNativeGrant: { findFirst: async () => null },
} as unknown as ProviderInterceptorDatabase;

function revokeThrough(providerResponse: () => Response) {
  const seen: URLSearchParams[] = [];
  const app = new Hono();
  app.use('/api/auth/*', createProviderInterceptors({
    database: emptyDatabase,
    tokens: {},
    provider: async (request) => {
      seen.push(new URLSearchParams(await request.text()));
      return providerResponse();
    },
  }));
  app.post('/api/auth/*', () => new Response('not dispatched here', { status: 418 }));
  const response = app.fetch(new Request('https://api.openkey.test/api/auth/oauth2/revoke', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'client_id=ordinary&token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmb28ifQ.invalid&token_type_hint=access_token',
  }));
  return { response, seen };
}

describe('unknown-token revoke', () => {
  test('forces token_type_hint=refresh_token and keeps every other parameter', async () => {
    const { response, seen } = revokeThrough(() => Response.json({ error: 'invalid_request', error_description: 'token not found' }, { status: 400 }));
    expect((await response).status).toBe(200);
    expect(Object.fromEntries(seen[0]!)).toEqual({
      client_id: 'ordinary',
      token: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmb28ifQ.invalid',
      token_type_hint: 'refresh_token',
    });
  });

  test('only the provider\'s unknown-token answers become 200', async () => {
    const cases: Array<[Response, number]> = [
      [Response.json({ error: 'invalid_request', error_description: 'token not found' }, { status: 400 }), 200],
      [Response.json({ error: 'invalid_token', error_description: 'refresh token not found' }, { status: 400 }), 200],
      [Response.json({ error: 'invalid_client', error_description: 'missing client' }, { status: 400 }), 400],
      [Response.json({ error: 'invalid_client' }, { status: 401 }), 401],
      [new Response(null, { status: 500 }), 500],
      [Response.json({ error: 'server_error' }, { status: 503 }), 503],
      [new Response('', { status: 200 }), 200],
    ];
    for (const [providerResponse, expected] of cases) {
      const { response } = revokeThrough(() => providerResponse.clone());
      const result = await response;
      expect(result.status, `${providerResponse.status}`).toBe(expected);
      if (expected === 200) expect(await result.text()).toBe('');
    }
  });

  test('a provider exception surfaces as a server error, never as 200', async () => {
    const { response } = revokeThrough(() => { throw new Error('database unavailable'); });
    expect((await response).status).toBe(500);
  });
});
