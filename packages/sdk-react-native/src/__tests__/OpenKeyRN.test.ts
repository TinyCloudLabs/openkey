import { describe, it, expect, mock, afterEach } from 'bun:test';
import { OpenKeyRN } from '../OpenKeyRN';
import type { BrowserOpener, OpenKeyRNFullConfig } from '../OpenKeyRN';
import { OpenKeyError } from '../types';
import type { AuthTokens } from '../types';

const TEST_HOST = 'https://auth.example.com';
const TEST_CLIENT_ID = 'test-client-id';
const TEST_REDIRECT_URI = 'myapp://callback';

const TOKEN_RESPONSE = {
  access_token: 'access-tok-123',
  id_token: 'id-tok-456',
  refresh_token: 'refresh-tok-789',
  expires_in: 3600,
};

function makeConfig(overrides?: Partial<OpenKeyRNFullConfig>): OpenKeyRNFullConfig {
  return {
    host: TEST_HOST,
    clientId: TEST_CLIENT_ID,
    redirectUri: TEST_REDIRECT_URI,
    openBrowser: mock(() => Promise.resolve()) as BrowserOpener,
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Helper to mock globalThis.fetch in a type-safe way.
 * Bun's mock() doesn't include the `preconnect` static method that
 * newer TypeScript typings expect on `typeof fetch`.
 */
function mockFetch(impl: (...args: Parameters<typeof fetch>) => ReturnType<typeof fetch>): void {
  globalThis.fetch = mock(impl) as unknown as typeof fetch;
}

// ─── Test Suite ──────────────────────────────────────────────────────────────

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('OpenKeyRN', () => {
  describe('signIn()', () => {
    it('constructs correct authorization URL', async () => {
      let capturedUrl = '';
      const openBrowser = mock(async (url: string) => {
        capturedUrl = url;
      }) as BrowserOpener;

      mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      // Give the async signIn a tick to call openBrowser
      await new Promise((r) => setTimeout(r, 10));

      expect(capturedUrl).toBeTruthy();
      const url = new URL(capturedUrl);
      expect(url.origin).toBe(TEST_HOST);
      expect(url.pathname).toBe('/api/auth/oauth2/authorize');
      expect(url.searchParams.get('client_id')).toBe(TEST_CLIENT_ID);
      expect(url.searchParams.get('redirect_uri')).toBe(TEST_REDIRECT_URI);
      expect(url.searchParams.get('response_type')).toBe('code');
      expect(url.searchParams.get('scope')).toBe('openid');
      expect(url.searchParams.get('code_challenge_method')).toBe('S256');
      expect(url.searchParams.get('state')).toBeTruthy();
      expect(url.searchParams.get('code_challenge')).toBeTruthy();

      // Clean up: complete the flow so the promise resolves
      const state = url.searchParams.get('state')!;
      client.handleCallback(`${TEST_REDIRECT_URI}?code=auth-code&state=${state}`);

      await signInPromise;
    });

    it('completes round-trip with handleCallback()', async () => {
      let capturedUrl = '';
      const openBrowser = mock(async (url: string) => {
        capturedUrl = url;
      }) as BrowserOpener;

      mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      // Wait for openBrowser to be called
      await new Promise((r) => setTimeout(r, 10));

      const url = new URL(capturedUrl);
      const state = url.searchParams.get('state')!;

      const handled = client.handleCallback(
        `${TEST_REDIRECT_URI}?code=auth-code-123&state=${state}`,
      );
      expect(handled).toBe(true);

      const tokens = await signInPromise;
      expect(tokens.accessToken).toBe('access-tok-123');
      expect(tokens.idToken).toBe('id-tok-456');
      expect(tokens.refreshToken).toBe('refresh-tok-789');
      expect(tokens.expiresIn).toBe(3600);
    });

    it('rejects with TIMEOUT when callback never arrives', async () => {
      mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));

      const client = new OpenKeyRN(makeConfig({ timeoutMs: 50 }));

      try {
        await client.signIn();
        // Should not reach here
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('TIMEOUT');
      }
    });
  });

  describe('handleCallback()', () => {
    it('returns false for non-matching URLs (no code/state)', () => {
      const client = new OpenKeyRN(makeConfig());
      expect(client.handleCallback('https://example.com/some-page')).toBe(false);
      expect(client.handleCallback('myapp://callback')).toBe(false);
      expect(client.handleCallback('myapp://callback?foo=bar')).toBe(false);
    });

    it('returns false for URL with code but no state', () => {
      const client = new OpenKeyRN(makeConfig());
      expect(client.handleCallback('myapp://callback?code=abc')).toBe(false);
    });

    it('returns false for URL with state but no code', () => {
      const client = new OpenKeyRN(makeConfig());
      expect(client.handleCallback('myapp://callback?state=xyz')).toBe(false);
    });

    it('returns false when state does not match any pending flow', () => {
      const client = new OpenKeyRN(makeConfig());
      expect(
        client.handleCallback('myapp://callback?code=abc&state=unknown-state'),
      ).toBe(false);
    });

    it('returns false for invalid URLs', () => {
      const client = new OpenKeyRN(makeConfig());
      expect(client.handleCallback('not a valid url')).toBe(false);
    });

    it('maps snake_case response to camelCase AuthTokens', async () => {
      let capturedUrl = '';
      const openBrowser = mock(async (url: string) => {
        capturedUrl = url;
      }) as BrowserOpener;

      const snakeCaseResponse = {
        access_token: 'at_snake',
        id_token: 'it_snake',
        refresh_token: 'rt_snake',
        expires_in: 7200,
      };

      mockFetch(() => Promise.resolve(jsonResponse(snakeCaseResponse)));

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      await new Promise((r) => setTimeout(r, 10));

      const url = new URL(capturedUrl);
      const state = url.searchParams.get('state')!;
      client.handleCallback(`${TEST_REDIRECT_URI}?code=code123&state=${state}`);

      const tokens = await signInPromise;
      expect(tokens).toEqual({
        accessToken: 'at_snake',
        idToken: 'it_snake',
        refreshToken: 'rt_snake',
        expiresIn: 7200,
      } satisfies AuthTokens);
    });
  });

  describe('exchangeCode (via signIn + handleCallback)', () => {
    it('rejects with UNKNOWN on non-ok token exchange response', async () => {
      let capturedUrl = '';
      const openBrowser = mock(async (url: string) => {
        capturedUrl = url;
      }) as BrowserOpener;

      mockFetch(() =>
        Promise.resolve(
          new Response('{"error":"invalid_grant"}', {
            status: 400,
            statusText: 'Bad Request',
          }),
        ),
      );

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      await new Promise((r) => setTimeout(r, 10));

      const url = new URL(capturedUrl);
      const state = url.searchParams.get('state')!;
      client.handleCallback(`${TEST_REDIRECT_URI}?code=bad-code&state=${state}`);

      try {
        await signInPromise;
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('UNKNOWN');
        expect((error as OpenKeyError).message).toContain('400');
      }
    });

    it('rejects with NETWORK_ERROR when fetch throws', async () => {
      let capturedUrl = '';
      const openBrowser = mock(async (url: string) => {
        capturedUrl = url;
      }) as BrowserOpener;

      mockFetch(() => Promise.reject(new TypeError('Network failure')));

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      await new Promise((r) => setTimeout(r, 10));

      const url = new URL(capturedUrl);
      const state = url.searchParams.get('state')!;
      client.handleCallback(`${TEST_REDIRECT_URI}?code=code123&state=${state}`);

      try {
        await signInPromise;
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('NETWORK_ERROR');
        expect((error as OpenKeyError).message).toContain('Network failure');
      }
    });
  });

  describe('refreshToken()', () => {
    it('sends correct POST body and returns tokens', async () => {
      let capturedBody = '';
      let capturedUrl = '';

      mockFetch(async (input, init) => {
        capturedUrl = typeof input === 'string' ? input : input.toString();
        capturedBody = init?.body as string;
        return jsonResponse(TOKEN_RESPONSE);
      });

      const client = new OpenKeyRN(makeConfig());
      const tokens = await client.refreshToken('my-refresh-token');

      expect(capturedUrl).toBe(`${TEST_HOST}/api/auth/oauth2/token`);

      const params = new URLSearchParams(capturedBody);
      expect(params.get('grant_type')).toBe('refresh_token');
      expect(params.get('refresh_token')).toBe('my-refresh-token');
      expect(params.get('client_id')).toBe(TEST_CLIENT_ID);

      expect(tokens.accessToken).toBe('access-tok-123');
      expect(tokens.idToken).toBe('id-tok-456');
      expect(tokens.refreshToken).toBe('refresh-tok-789');
      expect(tokens.expiresIn).toBe(3600);
    });

    it('throws NETWORK_ERROR when fetch fails', async () => {
      mockFetch(() => Promise.reject(new Error('connection refused')));

      const client = new OpenKeyRN(makeConfig());

      try {
        await client.refreshToken('some-token');
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('NETWORK_ERROR');
      }
    });

    it('throws UNKNOWN on non-ok response', async () => {
      mockFetch(() =>
        Promise.resolve(new Response('Unauthorized', { status: 401, statusText: 'Unauthorized' })),
      );

      const client = new OpenKeyRN(makeConfig());

      try {
        await client.refreshToken('expired-token');
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('UNKNOWN');
        expect((error as OpenKeyError).message).toContain('401');
      }
    });
  });

  describe('signOut()', () => {
    it('calls revocation endpoint with correct headers and body', async () => {
      let capturedUrl = '';
      let capturedHeaders: Record<string, string> = {};
      let capturedBody = '';

      mockFetch(async (input, init) => {
        capturedUrl = typeof input === 'string' ? input : input.toString();
        capturedHeaders = Object.fromEntries(
          Object.entries(init?.headers as Record<string, string>),
        );
        capturedBody = init?.body as string;
        return new Response(null, { status: 200 });
      });

      const client = new OpenKeyRN(makeConfig());
      await client.signOut('my-access-token');

      expect(capturedUrl).toBe(`${TEST_HOST}/api/auth/revoke`);
      expect(capturedHeaders['Authorization']).toBe('Bearer my-access-token');
      expect(capturedHeaders['Content-Type']).toBe('application/x-www-form-urlencoded');

      const params = new URLSearchParams(capturedBody);
      expect(params.get('token')).toBe('my-access-token');
    });

    it('throws NETWORK_ERROR when fetch fails', async () => {
      mockFetch(() => Promise.reject(new Error('offline')));

      const client = new OpenKeyRN(makeConfig());

      try {
        await client.signOut('token');
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('NETWORK_ERROR');
      }
    });

    it('throws NETWORK_ERROR on non-ok response', async () => {
      mockFetch(() =>
        Promise.resolve(new Response('Server Error', { status: 500, statusText: 'Internal Server Error' })),
      );

      const client = new OpenKeyRN(makeConfig());

      try {
        await client.signOut('token');
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('NETWORK_ERROR');
        expect((error as OpenKeyError).message).toContain('500');
      }
    });
  });
});
