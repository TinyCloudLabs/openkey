import { describe, it, expect, mock, afterEach } from 'bun:test';
import { OpenKeyRN } from '../OpenKeyRN';
import type { BrowserOpener, BrowserResult, OpenKeyRNFullConfig } from '../OpenKeyRN';
import { OpenKeyError } from '../types';
import type { AuthTokens, OpenKeySecureStore, OpenKeyRNDelegationConfig } from '../types';
import {
  OpenKeyNativeError,
  base64UrlDecode,
  generateSessionKeypair,
  sessionDidForPublicKey,
  SESSION_PROOF_HEADER,
} from '@openkey/core';
import type {
  NativeFetch,
  NativeFetchInit,
  NativeDelegationPermission,
} from '@openkey/core';

const TEST_HOST = 'https://auth.example.com';
const TEST_ISSUER = `${TEST_HOST}/api/auth`;
const TEST_CLIENT_ID = 'test-client-id';
const TEST_REDIRECT_URI = 'myapp://callback';
const TC_HOST = 'https://tee.node.tinycloud.xyz';

const TOKEN_RESPONSE = {
  access_token: 'access-tok-123',
  id_token: 'id-tok-456',
  refresh_token: 'refresh-tok-789',
  expires_in: 3600,
};

const METADATA = {
  issuer: TEST_ISSUER,
  authorization_endpoint: `${TEST_ISSUER}/oauth2/authorize`,
  token_endpoint: `${TEST_ISSUER}/oauth2/token`,
  pushed_authorization_request_endpoint: `${TEST_ISSUER}/oauth2/par`,
  tinycloud_delegation_renew_endpoint: `${TEST_ISSUER}/oauth2/tinycloud/renew`,
  tinycloud_delegation_revocation_endpoint: `${TEST_ISSUER}/oauth2/tinycloud/revoke`,
  code_challenge_methods_supported: ['S256'],
  authorization_response_iss_parameter_supported: true,
};

const KV_PERMISSION: NativeDelegationPermission = {
  service: 'tinycloud.kv',
  space: 'applications',
  path: 'xyz.tinycloud.testapp/threads/',
  actions: ['tinycloud.kv/get', 'tinycloud.kv/put'],
};

function makeConfig(overrides?: Partial<OpenKeyRNFullConfig>): OpenKeyRNFullConfig {
  return {
    host: TEST_HOST,
    clientId: TEST_CLIENT_ID,
    redirectUri: TEST_REDIRECT_URI,
    // Tests use a self-hosted issuer; production defaults to api.openkey.so.
    issuer: TEST_ISSUER,
    openBrowser: mock(() => Promise.resolve()) as BrowserOpener,
    ...overrides,
  };
}
/**
 * Legacy (void) opener that captures the authorization URL. `opened`
 * resolves the moment the SDK calls the opener, so tests wait on the real
 * signal instead of a wall-clock sleep.
 */
function captureOpener(): {
  openBrowser: BrowserOpener;
  opened: Promise<string>;
} {
  const { promise, resolve } = Promise.withResolvers<string>();
  const openBrowser = mock(async (url: string) => {
    resolve(url);
  }) as BrowserOpener;
  return { openBrowser, opened: promise };
}

/** Callback URL carrying a valid `iss` (RFC 9207) plus the given params. */
function callbackUrl(
  state: string,
  params: Record<string, string> = { code: 'auth-code' },
): string {
  const query = new URLSearchParams({ ...params, state, iss: TEST_ISSUER });
  return `${TEST_REDIRECT_URI}?${query.toString()}`;
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
function mockFetch(impl: typeof fetch): void {
  globalThis.fetch = mock(impl) as unknown as typeof fetch;
}

/** In-memory OpenKeySecureStore with the backing map exposed for assertions. */
function memoryStore(): OpenKeySecureStore & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    get: (key) => Promise.resolve(map.get(key) ?? null),
    set: (key, value) => {
      map.set(key, value);
      return Promise.resolve();
    },
    remove: (key) => {
      map.delete(key);
      return Promise.resolve();
    },
  };
}

/**
 * The verification-method id (`did:key:…#…`) belonging to the session key the
 * SDK published in the PAR `authorization_details` — needed to build a
 * delegation payload that passes client-side validation.
 */
function sessionKeyIdFromPar(parBody: string): string {
  const details = JSON.parse(
    new URLSearchParams(parBody).get('authorization_details')!,
  ) as { session_key: { x: string } }[];
  const did = sessionDidForPublicKey(base64UrlDecode(details[0]!.session_key.x));
  return `${did}#${did.slice('did:key:'.length)}`;
}

function delegationPayload(parBody: string): Record<string, unknown> {
  const details = JSON.parse(
    new URLSearchParams(parBody).get('authorization_details')!,
  ) as { permissions: NativeDelegationPermission[] }[];
  return {
    verificationMethod: sessionKeyIdFromPar(parBody),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    issuedAt: new Date(Date.now()).toISOString(),
    renewableUntil: new Date(Date.now() + 86_400_000).toISOString(),
    permissions: details[0]!.permissions,
    tinycloudHost: TC_HOST,
    // Real-shaped fields the verifier inspects (spec: siwe + signature
    // must reproduce delegationHeader and delegationCid).
    siwe: 'openkey.so wants you to sign in with your TinyCloud account',
    signature: '0x' + 'ab'.repeat(65),
    delegationHeader: { Authorization: 'SIWE siwe=deadbeef sig=beef' },
    delegationCid: 'bafydelegationcid',
  };
}

// ─── Test Suite ──────────────────────────────────────────────────────────────

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('OpenKeyRN', () => {
  describe('signIn()', () => {
    it('constructs correct authorization URL', async () => {
      const { openBrowser, opened } = captureOpener();
      mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      const capturedUrl = await opened;
      const url = new URL(capturedUrl);
      expect(url.origin).toBe(TEST_HOST);
      expect(url.pathname).toBe('/api/auth/oauth2/authorize');
      expect(url.searchParams.get('client_id')).toBe(TEST_CLIENT_ID);
      expect(url.searchParams.get('redirect_uri')).toBe(TEST_REDIRECT_URI);
      expect(url.searchParams.get('response_type')).toBe('code');
      expect(url.searchParams.get('scope')).toBe('openid email keys offline_access');
      expect(url.searchParams.get('code_challenge_method')).toBe('S256');
      expect(url.searchParams.get('state')).toBeTruthy();
      expect(url.searchParams.get('code_challenge')).toBeTruthy();

      // Clean up: complete the flow so the promise resolves
      const state = url.searchParams.get('state')!;
      client.handleCallback(callbackUrl(state));

      await signInPromise;
    });

    it('passes the redirect URI to the opener', async () => {
      let capturedRedirect = '';
      const openBrowser = mock(async (_url: string, redirectUri: string) => {
        capturedRedirect = redirectUri;
      }) as BrowserOpener;

      const client = new OpenKeyRN(makeConfig({ openBrowser, timeoutMs: 50 }));
      const signInPromise = client.signIn();
      signInPromise.catch(() => {});

      await expect(signInPromise).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(capturedRedirect).toBe(TEST_REDIRECT_URI);
    });

    it('uses custom scopes when configured', async () => {
      const { openBrowser, opened } = captureOpener();
      mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));

      const client = new OpenKeyRN(
        makeConfig({ openBrowser, scopes: ['openid', 'profile', 'custom:scope'] }),
      );
      const signInPromise = client.signIn();

      const url = new URL(await opened);
      expect(url.searchParams.get('scope')).toBe('openid profile custom:scope');

      const state = url.searchParams.get('state')!;
      client.handleCallback(callbackUrl(state));
      await signInPromise;
    });

    it('completes round-trip with handleCallback() (legacy void opener)', async () => {
      const { openBrowser, opened } = captureOpener();
      mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      const url = new URL(await opened);
      const state = url.searchParams.get('state')!;

      const handled = client.handleCallback(callbackUrl(state));
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

  describe('BrowserOpener result contract', () => {
    it('rejects USER_CANCELLED immediately on {type: "cancel"}', async () => {
      const openBrowser = mock(async (): Promise<BrowserResult | void> => ({
        type: 'cancel',
      })) as BrowserOpener;

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      // With the 5-minute default timeout, a resolved (not hung) rejection
      // proves immediate settlement.
      try {
        await client.signIn();
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('USER_CANCELLED');
      }
    });

    it('rejects USER_CANCELLED immediately on {type: "dismiss"}', async () => {
      const openBrowser = mock(async (): Promise<BrowserResult | void> => ({
        type: 'dismiss',
      })) as BrowserOpener;

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      await expect(client.signIn()).rejects.toMatchObject({
        code: 'USER_CANCELLED',
      });
    });

    it('feeds {type: "success", url} into the token exchange itself', async () => {
      mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));

      const openBrowser = mock(
        async (url: string): Promise<BrowserResult | void> => {
          const state = new URL(url).searchParams.get('state')!;
          return { type: 'success', url: callbackUrl(state) };
        },
      ) as BrowserOpener;

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const tokens = await client.signIn();
      expect(tokens.accessToken).toBe('access-tok-123');
    });

    it('rejects the pending flow when the opener throws', async () => {
      const openBrowser = mock(async () => {
        throw new Error('browser exploded');
      }) as BrowserOpener;

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      try {
        await client.signIn();
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('UNKNOWN');
        expect((error as OpenKeyError).message).toContain('browser exploded');
      }
    });

    it('passes a thrown OpenKeyError through', async () => {
      const openBrowser = mock(async () => {
        throw new OpenKeyError('USER_CANCELLED', 'user backed out');
      }) as BrowserOpener;

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      await expect(client.signIn()).rejects.toMatchObject({
        code: 'USER_CANCELLED',
      });
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

    it('returns false when state does not match and several flows are pending', async () => {
      // Two pending flows make a stray state un-attributable.
      const { promise: secondOpened, resolve: onSecond } =
        Promise.withResolvers<void>();
      let calls = 0;
      const openBrowser = mock(async () => {
        calls += 1;
        if (calls === 2) onSecond();
      }) as BrowserOpener;
      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const first = client.signIn();
      const second = client.signIn();
      first.catch(() => {});
      second.catch(() => {});
      // Both flows are registered once the SDK has opened both sessions.
      await secondOpened;

      expect(
        client.handleCallback(
          `${TEST_REDIRECT_URI}?code=abc&state=unknown-state&iss=${encodeURIComponent(TEST_ISSUER)}`,
        ),
      ).toBe(false);

      client.signOut();
      await expect(first).rejects.toMatchObject({ code: 'USER_CANCELLED' });
      await expect(second).rejects.toMatchObject({ code: 'USER_CANCELLED' });
    });
    it('returns false for invalid URLs', () => {
      const client = new OpenKeyRN(makeConfig());
      expect(client.handleCallback('not a valid url')).toBe(false);
    });

    it('maps snake_case response to camelCase AuthTokens', async () => {
      const { openBrowser, opened } = captureOpener();
      const snakeCaseResponse = {
        access_token: 'at_snake',
        id_token: 'it_snake',
        refresh_token: 'rt_snake',
        expires_in: 7200,
      };

      mockFetch(() => Promise.resolve(jsonResponse(snakeCaseResponse)));

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      const state = new URL(await opened).searchParams.get('state')!;
      client.handleCallback(callbackUrl(state, { code: 'code123' }));

      const tokens = await signInPromise;
      expect(tokens).toEqual({
        accessToken: 'at_snake',
        idToken: 'it_snake',
        refreshToken: 'rt_snake',
        expiresIn: 7200,
      } satisfies AuthTokens);
    });
  });

  describe('callback error and mismatch handling', () => {
    it('rejects ACCESS_DENIED on error=access_denied', async () => {
      const { openBrowser, opened } = captureOpener();
      mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));
      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      const state = new URL(await opened).searchParams.get('state')!;
      const handled = client.handleCallback(
        callbackUrl(state, {
          error: 'access_denied',
          error_description: 'user+denied',
        }),
      );
      expect(handled).toBe(true);

      try {
        await signInPromise;
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('ACCESS_DENIED');
      }
    });

    it('rejects SERVER on any other error=', async () => {
      const { openBrowser, opened } = captureOpener();
      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      const state = new URL(await opened).searchParams.get('state')!;
      client.handleCallback(
        callbackUrl(state, { error: 'invalid_request_uri' }),
      );

      try {
        await signInPromise;
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('SERVER');
      }
    });

    it('rejects STATE_MISMATCH when the opener returns a wrong state', async () => {
      const openBrowser = mock(
        async (): Promise<BrowserResult | void> => ({
          type: 'success',
          url: callbackUrl('some-other-state'),
        }),
      ) as BrowserOpener;

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      try {
        await client.signIn();
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('STATE_MISMATCH');
      }
    });

    it('ignores a stray callback whose state matches no flow', async () => {
      const { openBrowser, opened } = captureOpener();
      mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));
      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      const state = new URL(await opened).searchParams.get('state')!;
      // Not this flow's callback: ignored, and the flow stays alive.
      expect(client.handleCallback(callbackUrl('some-other-state'))).toBe(
        false,
      );

      // The real callback still completes the flow.
      expect(client.handleCallback(callbackUrl(state))).toBe(true);
      await signInPromise;
    });

    it('rejects SERVER on error=consent_required', async () => {
      const { openBrowser, opened } = captureOpener();
      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      const state = new URL(await opened).searchParams.get('state')!;
      client.handleCallback(callbackUrl(state, { error: 'consent_required' }));

      try {
        await signInPromise;
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('SERVER');
      }
    });

    it('rejects STATE_MISMATCH on an iss mismatch', async () => {
      const { openBrowser, opened } = captureOpener();
      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      const state = new URL(await opened).searchParams.get('state')!;
      const handled = client.handleCallback(
        `${TEST_REDIRECT_URI}?code=c&state=${state}&iss=${encodeURIComponent('https://evil.example.com/api/auth')}`,
      );
      expect(handled).toBe(true);

      try {
        await signInPromise;
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyError);
        expect((error as OpenKeyError).code).toBe('STATE_MISMATCH');
      }
    });
  });

  describe('exchangeCode (via signIn + handleCallback)', () => {
    it('rejects with UNKNOWN on non-ok token exchange response', async () => {
      const { openBrowser, opened } = captureOpener();
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

      const state = new URL(await opened).searchParams.get('state')!;
      client.handleCallback(callbackUrl(state, { code: 'bad-code' }));

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
      const { openBrowser, opened } = captureOpener();
      mockFetch(() => Promise.reject(new TypeError('Network failure')));

      const client = new OpenKeyRN(makeConfig({ openBrowser }));
      const signInPromise = client.signIn();

      const state = new URL(await opened).searchParams.get('state')!;
      client.handleCallback(callbackUrl(state, { code: 'code123' }));

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

  describe('resource indicator', () => {
    const successOpener = (): BrowserOpener =>
      mock(async (url: string): Promise<BrowserResult | void> => {
        const state = new URL(url).searchParams.get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;

    it('sends resource when explicitly configured', async () => {
      let capturedBody = '';
      mockFetch((_input, init) => {
        capturedBody = init?.body as string;
        return Promise.resolve(jsonResponse(TOKEN_RESPONSE));
      });

      const client = new OpenKeyRN(
        makeConfig({
          openBrowser: successOpener(),
          resource: 'https://resource.example.com',
        }),
      );

      await client.signIn();

      expect(new URLSearchParams(capturedBody).get('resource')).toBe(
        'https://resource.example.com',
      );
    });

    it('does not send resource by default', async () => {
      let capturedBody = '';
      mockFetch((_input, init) => {
        capturedBody = init?.body as string;
        return Promise.resolve(jsonResponse(TOKEN_RESPONSE));
      });

      const client = new OpenKeyRN(
        makeConfig({ openBrowser: successOpener() }),
      );

      await client.signIn();

      expect(new URLSearchParams(capturedBody).get('resource')).toBeNull();
    });
  });

  describe('refreshToken()', () => {
    it('sends correct POST body and returns tokens', async () => {
      let capturedBody = '';
      let capturedUrl = '';

      mockFetch((input, init) => {
        capturedUrl = typeof input === 'string' ? input : input.toString();
        capturedBody = init?.body as string;
        return Promise.resolve(jsonResponse(TOKEN_RESPONSE));
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

      mockFetch((input, init) => {
        capturedUrl = typeof input === 'string' ? input : input.toString();
        capturedHeaders = Object.fromEntries(
          Object.entries(init?.headers as Record<string, string>),
        );
        capturedBody = init?.body as string;
        return Promise.resolve(new Response(null, { status: 200 }));
      });

      const client = new OpenKeyRN(makeConfig());
      await client.signOut('my-access-token');

      expect(capturedUrl).toBe(`${TEST_HOST}/api/auth/revoke`);
      expect(capturedHeaders['Authorization']).toBe('Bearer my-access-token');
      expect(capturedHeaders['Content-Type']).toBe('application/x-www-form-urlencoded');

      const params = new URLSearchParams(capturedBody);
      expect(params.get('token')).toBe('my-access-token');
    });

    it('throws NETWORK_ERROR when the revoke fetch fails', async () => {
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

  describe('delegation mode', () => {
    function makeDelegationConfig(
      store: OpenKeySecureStore,
      fetchFn: NativeFetch,
      overrides?: Partial<OpenKeyRNFullConfig>,
      verifyDelegation?: OpenKeyRNDelegationConfig['verifyDelegation'],
    ): OpenKeyRNFullConfig {
      return makeConfig({
        delegation: {
          permissions: [KV_PERMISSION],
          tinycloudHost: TC_HOST,
          storage: store,
          verifyDelegation:
            verifyDelegation ?? (() => Promise.resolve()),
          fetchFn,
          sleepFn: () => Promise.resolve(),
        },
        ...overrides,
      });
    }

    /**
     * Fetch stub for the full delegation sign-in: discovery → PAR →
     * authorize (opener) → token exchange carrying `tinycloud_delegation`.
     */
    function delegationFetch(captured: {
      parBody?: string;
      tokenBody?: string;
      tokenProof?: string;
    }): NativeFetch {
      return (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/par')) {
          captured.parBody = init!.body!;
          return Promise.resolve(
            jsonResponse(
              { request_uri: 'urn:ietf:params:oauth:request_uri:req-1', expires_in: 90 },
              201,
            ),
          );
        }
        if (url.endsWith('/oauth2/token')) {
          captured.tokenBody = init!.body!;
          captured.tokenProof = init!.headers![SESSION_PROOF_HEADER];
          return Promise.resolve(
            jsonResponse({
              access_token: 'nat-access',
              refresh_token: 'nat-refresh-1',
              expires_in: 300,
              tinycloud_delegation: delegationPayload(captured.parBody!),
            }),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
    }

    it('signIn returns {tokens, delegation} and persists the session', async () => {
      const store = memoryStore();
      const captured: { parBody?: string; tokenBody?: string } = {};
      const fetchFn = delegationFetch(captured);

      let authUrl = '';
      const openBrowser = mock(async (url: string): Promise<BrowserResult | void> => {
        authUrl = url;
        // The state was pushed inside the PAR, not the authorize URL.
        const state = new URLSearchParams(captured.parBody!).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;

      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser, scopes: ['email'] }),
      );
      const result = await client.signIn();

      // PAR carried the delegation request.
      const parParams = new URLSearchParams(captured.parBody!);
      expect(parParams.get('scope')).toBe(
        'openid offline_access tinycloud:delegation email',
      );
      expect(parParams.get('code_challenge_method')).toBe('S256');
      const details = JSON.parse(parParams.get('authorization_details')!);
      expect(details[0].type).toBe('tinycloud_delegation');
      expect(details[0].session_key.kty).toBe('OKP');
      // capabilities/read was prepended to the requested permissions.
      expect(details[0].permissions[0].service).toBe('tinycloud.capabilities');

      // The authorize URL only carries client_id + request_uri.
      const authorize = new URL(authUrl);
      expect(authorize.pathname).toBe('/api/auth/oauth2/authorize');
      expect(authorize.searchParams.get('client_id')).toBe(TEST_CLIENT_ID);
      expect(authorize.searchParams.get('request_uri')).toBe(
        'urn:ietf:params:oauth:request_uri:req-1',
      );
      expect(authorize.searchParams.get('scope')).toBeNull();

      // Result carries the validated delegation.
      expect(result.accessToken).toBe('nat-access');
      expect(result.refreshToken).toBe('nat-refresh-1');
      expect(result.delegation).toBeDefined();
      expect(result.delegation!.tinycloudHost).toBe(TC_HOST);
      expect(result.delegation!.verificationMethod).toMatch(/^did:key:z.+#z/);

      // The session (private key + refresh token) was persisted.
      const record = JSON.parse(
        store.map.get(`openkey:tinycloud-delegation:${TEST_CLIENT_ID}`)!,
      );
      expect(record.refreshToken).toBe('nat-refresh-1');
      expect(typeof record.privateJwk.d).toBe('string');
    });

    it('renew() rotates the refresh token with a session proof and persists it', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      await store.set(`openkey:tinycloud-delegation:${TEST_CLIENT_ID}`, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-old',
        permissions: [KV_PERMISSION],
      }));

      let renewBody = '';
      let renewProof = '';
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          renewBody = init!.body!;
          renewProof = init!.headers![SESSION_PROOF_HEADER]!;
          return Promise.resolve(
            jsonResponse({
              refresh_token: 'rt-new',
              tinycloud_delegation: {
                verificationMethod: sessionKey.keyId,
                expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));
      const result = await client.renew();

      const params = new URLSearchParams(renewBody);
      expect(params.get('refresh_token')).toBe('rt-old');
      expect(params.get('client_id')).toBe(TEST_CLIENT_ID);
      expect(renewProof.split('.')).toHaveLength(3);

      expect(result.refreshToken).toBe('rt-new');
      expect(result.delegation.tinycloudHost).toBe(TC_HOST);

      const record = JSON.parse(
        store.map.get(`openkey:tinycloud-delegation:${TEST_CLIENT_ID}`)!,
      );
      expect(record.refreshToken).toBe('rt-new');
    });

    it('renew() rejects UNAVAILABLE without delegation config', async () => {
      const client = new OpenKeyRN(makeConfig());
      try {
        await client.renew();
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyNativeError);
        expect((error as OpenKeyNativeError).code).toBe('UNAVAILABLE');
      }
    });

    it('renew() rejects NOT_SIGNED_IN without a stored session', async () => {
      const store = memoryStore();
      const fetchFn: NativeFetch = () =>
        Promise.reject(new Error('fetch should not be called'));
      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));
      try {
        await client.renew();
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyNativeError);
        expect((error as OpenKeyNativeError).code).toBe('NOT_SIGNED_IN');
      }
    });

    it('fails closed when verifyDelegation is missing', () => {
      const store = memoryStore();
      const fetchFn: NativeFetch = () =>
        Promise.reject(new Error('fetch should not be called'));
      const delegation = {
        permissions: [KV_PERMISSION],
        tinycloudHost: TC_HOST,
        storage: store,
        fetchFn,
      } as Omit<OpenKeyRNDelegationConfig, 'verifyDelegation'> &
        Partial<Pick<OpenKeyRNDelegationConfig, 'verifyDelegation'>>;

      try {
        new OpenKeyRN(makeConfig({ delegation }));
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyNativeError);
        expect((error as OpenKeyNativeError).code).toBe('UNAVAILABLE');
      }
    });

    it('calls verifyDelegation on sign-in and rejects on failure', async () => {
      const store = memoryStore();
      const captured: { parBody?: string } = {};
      const fetchFn = delegationFetch(captured);
      const verifyDelegation = mock(() =>
        Promise.reject(new Error('bad signature')),
      );

      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(captured.parBody!).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;

      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }, verifyDelegation),
      );

      let thrown: unknown;
      try {
        await client.signIn();
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('SERVER');
      // The code was exchanged, so the live refresh token rides the error.
      expect((thrown as OpenKeyNativeError).rotatedRefreshToken).toBe(
        'nat-refresh-1',
      );
      expect(verifyDelegation).toHaveBeenCalledTimes(1);
    });

    it('renews immediately when the new delegation is already in the lead window', async () => {
      const store = memoryStore();
      let renewCalls = 0;
      let parBody = '';
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/par')) {
          parBody = init!.body!;
          return Promise.resolve(
            jsonResponse(
              { request_uri: 'urn:ietf:params:oauth:request_uri:req-1', expires_in: 90 },
              201,
            ),
          );
        }
        if (url.endsWith('/oauth2/token')) {
          return Promise.resolve(
            jsonResponse({
              access_token: 'nat-access',
              refresh_token: 'rt-initial',
              expires_in: 300,
              tinycloud_delegation: {
                // expiresAt − issuedAt lead exceeded → needs renewal now.
                verificationMethod: sessionKeyIdFromPar(parBody),
                issuedAt: new Date(Date.now() - 3_600_000).toISOString(),
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          renewCalls += 1;
          return Promise.resolve(
            jsonResponse({
              refresh_token: 'rt-renewed',
              tinycloud_delegation: {
                verificationMethod: sessionKeyIdFromPar(parBody),
                expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(parBody).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;

      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );
      const result = await client.signIn();

      expect(renewCalls).toBe(1);
      expect(result.refreshToken).toBe('rt-renewed');
      const record = JSON.parse(
        store.map.get(`openkey:tinycloud-delegation:${TEST_CLIENT_ID}`)!,
      );
      expect(record.refreshToken).toBe('rt-renewed');
    });

    it('rejects signIn with a typed error carrying the token when persist fails', async () => {
      const base = memoryStore();
      const store: OpenKeySecureStore & { map: Map<string, string> } = {
        ...base,
        set: () => Promise.reject(new Error('disk full')),
      };
      const captured: { parBody?: string } = {};
      const fetchFn = delegationFetch(captured);

      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(captured.parBody!).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;

      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );

      let thrown: unknown;
      try {
        await client.signIn();
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('NETWORK');
      expect((thrown as OpenKeyNativeError).rotatedRefreshToken).toBe(
        'nat-refresh-1',
      );
    });

    it('renew() rejects with rotatedRefreshToken when persist fails', async () => {
      const base = memoryStore();
      const sessionKey = generateSessionKeypair();
      const key = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
      await base.set(key, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-old',
        permissions: [KV_PERMISSION],
      }));
      const store: OpenKeySecureStore & { map: Map<string, string> } = {
        ...base,
        set: (k, v) =>
          k === key ? Promise.reject(new Error('disk full')) : base.set(k, v),
      };

      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          return Promise.resolve(
            jsonResponse({
              refresh_token: 'rt-new',
              tinycloud_delegation: {
                verificationMethod: sessionKey.keyId,
                expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));

      let thrown: unknown;
      try {
        await client.renew();
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('NETWORK');
      expect((thrown as OpenKeyNativeError).rotatedRefreshToken).toBe('rt-new');
    });

    it('signOut() rejects when the storage wipe fails', async () => {
      const base = memoryStore();
      const sessionKey = generateSessionKeypair();
      const key = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
      await base.set(key, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-old',
        permissions: [KV_PERMISSION],
      }));
      const store: OpenKeySecureStore & { map: Map<string, string> } = {
        ...base,
        remove: () => Promise.reject(new Error('locked')),
      };
      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        return Promise.resolve(new Response(null, { status: 200 }));
      };

      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));

      let thrown: unknown;
      try {
        await client.signOut();
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('NETWORK');
    });

    it('an in-flight renew() rejects NOT_SIGNED_IN after signOut()', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      await store.set(`openkey:tinycloud-delegation:${TEST_CLIENT_ID}`, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-old',
        permissions: [KV_PERMISSION],
      }));

      const { promise: renewReached, resolve: releaseRenew } =
        Promise.withResolvers<void>();
      const fetchFn: NativeFetch = async (url: string) => {
        if (url.includes('/.well-known/')) {
          return jsonResponse(METADATA);
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          releaseRenew();
          // The renew response only lands after signOut has run.
          await signOutDone.promise;
          return jsonResponse({
            refresh_token: 'rt-new',
            tinycloud_delegation: {
              verificationMethod: sessionKey.keyId,
              expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
              permissions: [KV_PERMISSION],
              tinycloudHost: TC_HOST,
            },
          });
        }
        return new Response(null, { status: 200 });
      };
      const signOutDone = Promise.withResolvers<void>();

      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));
      const renewPromise = client.renew();
      renewPromise.catch(() => {});
      await renewReached;

      await client.signOut();
      signOutDone.resolve();

      let thrown: unknown;
      try {
        await renewPromise;
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('NOT_SIGNED_IN');
      // The rotated token was never persisted over the wiped session.
      expect(store.map.has(`openkey:tinycloud-delegation:${TEST_CLIENT_ID}`)).toBe(
        false,
      );
    });

    it('refreshToken() rejects UNAVAILABLE in delegation mode', async () => {
      const store = memoryStore();
      const fetchFn: NativeFetch = () =>
        Promise.reject(new Error('fetch should not be called'));
      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));

      let thrown: unknown;
      try {
        await client.refreshToken('rt');
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('UNAVAILABLE');
    });

    it('signOut() wipes locally but rejects when the revoke fails transiently', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      const key = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
      await store.set(key, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-old',
        permissions: [KV_PERMISSION],
      }));

      let revokeCalls = 0;
      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revokeCalls += 1;
          // 503 temporarily_unavailable on every attempt — core retries
          // once internally, then throws TEMPORARILY_UNAVAILABLE.
          return Promise.resolve(
            jsonResponse({ error: 'temporarily_unavailable' }, 503),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));

      let thrown: unknown;
      try {
        await client.signOut();
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('TEMPORARILY_UNAVAILABLE');
      expect(revokeCalls).toBe(2); // the spec's single internal retry
      // The local session was still wiped — the grant may still be active
      // server-side, so the caller can retry signOut().
      expect(store.map.has(key)).toBe(false);
    });

    it('signOut() resolves on a terminal revoke failure and still wipes', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      const key = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
      await store.set(key, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-old',
        permissions: [KV_PERMISSION],
      }));

      let revokeCalls = 0;
      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revokeCalls += 1;
          // Terminal: the grant is already unusable server-side.
          return Promise.resolve(
            jsonResponse({ error: 'invalid_session_proof' }, 401),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));
      await client.signOut(); // resolves — terminal revoke is success
      expect(revokeCalls).toBe(1);
      expect(store.map.has(key)).toBe(false);
    });

    it('discards an exchange that lands after signOut() and revokes the orphan', async () => {
      const store = memoryStore();
      const key = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
      const { promise: exchangeReached, resolve: reachedExchange } =
        Promise.withResolvers<void>();
      const { promise: exchangeGate, resolve: releaseExchange } =
        Promise.withResolvers<void>();
      let parBody = '';
      let revokedToken = '';
      const fetchFn: NativeFetch = async (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return jsonResponse(METADATA);
        }
        if (url.endsWith('/oauth2/par')) {
          parBody = init!.body!;
          return jsonResponse(
            { request_uri: 'urn:ietf:params:oauth:request_uri:req-1', expires_in: 90 },
            201,
          );
        }
        if (url.endsWith('/oauth2/token')) {
          reachedExchange();
          // The exchange response only lands after signOut has run.
          await exchangeGate;
          return jsonResponse({
            access_token: 'nat-access',
            refresh_token: 'rt-orphaned',
            expires_in: 300,
            tinycloud_delegation: delegationPayload(parBody),
          });
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revokedToken = new URLSearchParams(init!.body!).get('refresh_token')!;
          return new Response(null, { status: 200 });
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(parBody).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;

      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );
      const signInPromise = client.signIn();
      signInPromise.catch(() => {});

      await exchangeReached;
      await client.signOut();
      releaseExchange();

      let thrown: unknown;
      try {
        await signInPromise;
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('NOT_SIGNED_IN');
      // The grant left behind by the discarded exchange was revoked
      // best-effort, and no session was persisted over the wipe.
      expect(revokedToken).toBe('rt-orphaned');
      expect(store.map.has(key)).toBe(false);
    });

    it('a failed immediate renew keeps the initial session persisted', async () => {
      const store = memoryStore();
      const key = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
      let parBody = '';
      let renewCalls = 0;
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/par')) {
          parBody = init!.body!;
          return Promise.resolve(
            jsonResponse(
              { request_uri: 'urn:ietf:params:oauth:request_uri:req-1', expires_in: 90 },
              201,
            ),
          );
        }
        if (url.endsWith('/oauth2/token')) {
          return Promise.resolve(
            jsonResponse({
              access_token: 'nat-access',
              refresh_token: 'rt-initial',
              expires_in: 300,
              tinycloud_delegation: {
                // expiresAt inside the lead window → immediate renew.
                verificationMethod: sessionKeyIdFromPar(parBody),
                issuedAt: new Date(Date.now() - 3_600_000).toISOString(),
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          renewCalls += 1;
          return Promise.resolve(
            jsonResponse({ error: 'temporarily_unavailable' }, 503),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(parBody).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;

      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );

      let thrown: unknown;
      try {
        await client.signIn();
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('TEMPORARILY_UNAVAILABLE');
      expect(renewCalls).toBe(2); // spec's single internal retry
      // The initial exchange session survived — its refresh token is live.
      const record = JSON.parse(store.map.get(key)!);
      expect(record.refreshToken).toBe('rt-initial');
    });

    it('wraps a verifyDelegation failure on renew as SERVER and persists the rotated token', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      const key = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
      await store.set(key, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-old',
        permissions: [KV_PERMISSION],
      }));

      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          return Promise.resolve(
            jsonResponse({
              refresh_token: 'rt-new',
              tinycloud_delegation: {
                verificationMethod: sessionKey.keyId,
                expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const verifyDelegation = mock(() =>
        Promise.reject(new Error('cid mismatch')),
      );
      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, undefined, verifyDelegation),
      );

      let thrown: unknown;
      try {
        await client.renew();
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OpenKeyNativeError);
      expect((thrown as OpenKeyNativeError).code).toBe('SERVER');
      // The rotated token is live and the old one dead: it rides the error
      // AND was persisted best-effort.
      expect((thrown as OpenKeyNativeError).rotatedRefreshToken).toBe('rt-new');
      const record = JSON.parse(store.map.get(key)!);
      expect(record.refreshToken).toBe('rt-new');
    });

    it('renew() on INVALID_GRANT wipes the local session (local sign-out)', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      const key = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
      await store.set(key, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-old',
        permissions: [KV_PERMISSION],
      }));

      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          return Promise.resolve(jsonResponse({ error: 'invalid_grant' }, 400));
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));

      let thrown: unknown;
      try {
        await client.renew();
        expect(true).toBe(false);
      } catch (error) {
        thrown = error;
      }
      expect((thrown as OpenKeyNativeError).code).toBe('INVALID_GRANT');
      expect(store.map.has(key)).toBe(false);
      // And renew() now reports signed-out.
      await expect(client.renew()).rejects.toMatchObject({
        code: 'NOT_SIGNED_IN',
      });
    });

    it('concurrent renew()s with different options queue behind each other', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      const key = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
      await store.set(key, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-0',
        permissions: [KV_PERMISSION],
      }));

      const { promise: firstReached, resolve: reachedFirst } =
        Promise.withResolvers<void>();
      const { promise: firstGate, resolve: releaseFirst } =
        Promise.withResolvers<void>();
      const renewBodies: string[] = [];
      let renewCalls = 0;
      const fetchFn: NativeFetch = async (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return jsonResponse(METADATA);
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          renewCalls += 1;
          renewBodies.push(init!.body!);
          if (renewCalls === 1) {
            reachedFirst();
            await firstGate;
          }
          return jsonResponse({
            refresh_token: `rt-${renewCalls}`,
            tinycloud_delegation: {
              verificationMethod: sessionKey.keyId,
              expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
              permissions: [KV_PERMISSION],
              tinycloudHost: TC_HOST,
            },
          });
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));

      const p1 = client.renew({ siweNonce: 'nonce-aaa' });
      await firstReached;
      // Different options: must queue, not share the in-flight promise.
      const p2 = client.renew({ siweNonce: 'nonce-bbb' });
      expect(renewCalls).toBe(1);
      releaseFirst();

      const [r1, r2] = await Promise.all([p1, p2]);
      expect(r1.refreshToken).toBe('rt-1');
      expect(r2.refreshToken).toBe('rt-2');
      expect(renewCalls).toBe(2);
      // The queued renew ran sequentially and sent its own options plus the
      // token the first renew rotated to.
      expect(new URLSearchParams(renewBodies[0]!).get('siwe_nonce')).toBe(
        'nonce-aaa',
      );
      expect(new URLSearchParams(renewBodies[0]!).get('refresh_token')).toBe(
        'rt-0',
      );
      expect(new URLSearchParams(renewBodies[1]!).get('siwe_nonce')).toBe(
        'nonce-bbb',
      );
      expect(new URLSearchParams(renewBodies[1]!).get('refresh_token')).toBe(
        'rt-1',
      );
      const record = JSON.parse(store.map.get(key)!);
      expect(record.refreshToken).toBe('rt-2');
    });

    it('concurrent renew()s with identical options share the in-flight renewal', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      await store.set(`openkey:tinycloud-delegation:${TEST_CLIENT_ID}`, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken: 'rt-0',
        permissions: [KV_PERMISSION],
      }));

      let renewCalls = 0;
      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          renewCalls += 1;
          return Promise.resolve(
            jsonResponse({
              refresh_token: 'rt-1',
              tinycloud_delegation: {
                verificationMethod: sessionKey.keyId,
                expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));
      const [r1, r2] = await Promise.all([
        client.renew({ siweNonce: 'nonce-aaa' }),
        client.renew({ siweNonce: 'nonce-aaa' }),
      ]);
      expect(renewCalls).toBe(1);
      expect(r1.refreshToken).toBe('rt-1');
      expect(r2.refreshToken).toBe('rt-1');
    });

    // ── Round 3: terminal outcomes, sign-in errors, pending revoke,
    //    normalized single-flight, approved-set retention ──

    const SESSION_KEY = `openkey:tinycloud-delegation:${TEST_CLIENT_ID}`;
    const PENDING_KEY = `openkey:tinycloud-delegation-pending-revoke:${TEST_CLIENT_ID}`;
    const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

    /** A stored pending-revoke entry (one failed attempt, 7-day expiry). */
    function pendingEntry(
      sessionKey: ReturnType<typeof generateSessionKeypair>,
      refreshToken: string,
      overrides?: { attempts?: number; expiresAt?: number },
    ) {
      return {
        privateJwk: sessionKey.privateJwk,
        refreshToken,
        attempts: 1,
        expiresAt: Date.now() + SEVEN_DAYS_MS,
        ...overrides,
      };
    }
    const CAP_READ: NativeDelegationPermission = {
      service: 'tinycloud.capabilities',
      space: 'applications',
      path: '',
      actions: ['tinycloud.capabilities/read'],
    };
    const KV_PERMISSION_2: NativeDelegationPermission = {
      service: 'tinycloud.kv',
      space: 'applications',
      path: 'xyz.tinycloud.testapp/connectors/',
      actions: ['tinycloud.kv/get'],
    };

    async function seedSession(
      store: OpenKeySecureStore,
      refreshToken = 'rt-old',
    ): Promise<ReturnType<typeof generateSessionKeypair>> {
      const sessionKey = generateSessionKeypair();
      await store.set(SESSION_KEY, JSON.stringify({
        privateJwk: sessionKey.privateJwk,
        refreshToken,
        permissions: [KV_PERMISSION],
      }));
      return sessionKey;
    }

    /** Store whose remove() of `key` resolves `removed`. */
    function storeWatchingRemove(key: string): {
      store: OpenKeySecureStore & { map: Map<string, string> };
      removed: Promise<void>;
    } {
      const base = memoryStore();
      const { promise: removed, resolve } = Promise.withResolvers<void>();
      return {
        removed,
        store: {
          ...base,
          remove: async (k) => {
            await base.remove(k);
            if (k === key) resolve();
          },
        },
      };
    }

    async function rejection(promise: Promise<unknown>): Promise<OpenKeyNativeError> {
      try {
        await promise;
      } catch (error) {
        expect(error).toBeInstanceOf(OpenKeyNativeError);
        return error as OpenKeyNativeError;
      }
      throw new Error('expected a rejection');
    }

    it('a terminal immediate renew persists nothing and revokes the rotated grant', async () => {
      const store = memoryStore();
      let parBody = '';
      const revoked: string[] = [];
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/par')) {
          parBody = init!.body!;
          return Promise.resolve(
            jsonResponse(
              { request_uri: 'urn:ietf:params:oauth:request_uri:req-1', expires_in: 90 },
              201,
            ),
          );
        }
        if (url.endsWith('/oauth2/token')) {
          return Promise.resolve(
            jsonResponse({
              access_token: 'nat-access',
              refresh_token: 'rt-initial',
              expires_in: 300,
              tinycloud_delegation: {
                // Inside the lead window → immediate renew.
                verificationMethod: sessionKeyIdFromPar(parBody),
                issuedAt: new Date(Date.now() - 3_600_000).toISOString(),
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          // 2xx that rotated the token, but hosting failed → terminal
          // SPACE_UNAVAILABLE carrying rotatedRefreshToken.
          return Promise.resolve(
            jsonResponse({
              refresh_token: 'rt-rotated',
              tinycloud_delegation: {
                verificationMethod: sessionKeyIdFromPar(parBody),
                expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
                hosting: 'failed',
              },
            }),
          );
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revoked.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          return Promise.resolve(new Response(null, { status: 200 }));
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(parBody).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;

      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );
      const thrown = await rejection(client.signIn());
      expect(thrown.code).toBe('SPACE_UNAVAILABLE');
      expect(thrown.rotatedRefreshToken).toBe('rt-rotated');
      // Terminal: nothing persisted (not even the rotated token), and the
      // rotated grant was revoked best-effort.
      expect(store.map.has(SESSION_KEY)).toBe(false);
      expect(revoked).toEqual(['rt-rotated']);
      await expect(client.renew()).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    });

    it('a terminal exchange keeps the existing session and revokes the new grant', async () => {
      const store = memoryStore();
      await seedSession(store, 'rt-existing');
      const before = store.map.get(SESSION_KEY);
      const captured: { parBody?: string } = {};
      const revoked: string[] = [];
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/par')) {
          captured.parBody = init!.body!;
          return Promise.resolve(
            jsonResponse(
              { request_uri: 'urn:ietf:params:oauth:request_uri:req-1', expires_in: 90 },
              201,
            ),
          );
        }
        if (url.endsWith('/oauth2/token')) {
          return Promise.resolve(
            jsonResponse({
              access_token: 'nat-access',
              refresh_token: 'rt-new-grant',
              expires_in: 300,
              tinycloud_delegation: {
                ...delegationPayload(captured.parBody!),
                hosting: 'failed',
              },
            }),
          );
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revoked.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          return Promise.resolve(new Response(null, { status: 200 }));
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(captured.parBody!).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;

      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );
      const thrown = await rejection(client.signIn());
      expect(thrown.code).toBe('SPACE_UNAVAILABLE');
      expect(thrown.rotatedRefreshToken).toBe('rt-new-grant');
      expect(revoked).toEqual(['rt-new-grant']);
      // The stored session predates this attempt: untouched.
      expect(store.map.get(SESSION_KEY)).toBe(before!);
    });

    it('ACCESS_DENIED, USER_CANCELLED and STATE_MISMATCH keep an existing session', async () => {
      const store = memoryStore();
      await seedSession(store, 'rt-existing');
      const before = store.map.get(SESSION_KEY);
      const captured: { parBody?: string } = {};
      const fetchFn = delegationFetch(captured);

      const outcomes: [string, () => BrowserResult][] = [
        ['ACCESS_DENIED', () => {
          const state = new URLSearchParams(captured.parBody!).get('state')!;
          return { type: 'success', url: callbackUrl(state, { error: 'access_denied' }) };
        }],
        ['USER_CANCELLED', () => ({ type: 'cancel' })],
        ['STATE_MISMATCH', () => ({ type: 'success', url: callbackUrl('wrong-state') })],
      ];
      for (const [code, result] of outcomes) {
        const openBrowser = mock(async () => result()) as BrowserOpener;
        const client = new OpenKeyRN(
          makeDelegationConfig(store, fetchFn, { openBrowser }),
        );
        let thrown: unknown;
        try {
          await client.signIn();
          expect(true).toBe(false);
        } catch (error) {
          thrown = error;
        }
        expect((thrown as { code: string }).code).toBe(code);
        expect(store.map.get(SESSION_KEY)).toBe(before!);
      }
    });

    it('signOut() on a transient revoke failure keeps a pending revoke and reads signed out', async () => {
      const store = memoryStore();
      const sessionKey = await seedSession(store, 'rt-old');

      let revokeStatus = 503;
      const revoked: string[] = [];
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revoked.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          return Promise.resolve(
            revokeStatus === 200
              ? new Response(null, { status: 200 })
              : jsonResponse({ error: 'temporarily_unavailable' }, revokeStatus),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));

      const thrown = await rejection(client.signOut());
      expect(thrown.code).toBe('TEMPORARILY_UNAVAILABLE');
      // Signed out: no session record, renew() reports NOT_SIGNED_IN.
      expect(store.map.has(SESSION_KEY)).toBe(false);
      await expect(client.renew()).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
      // The pending revoke holds the session key, refresh token and its
      // retry bounds: one attempt made, expiry within the 7-day TTL (the
      // seeded record predates expiry tracking, so now + 7 days).
      const pendingRecord = JSON.parse(store.map.get(PENDING_KEY)!);
      expect(pendingRecord).toEqual([
        {
          privateJwk: sessionKey.privateJwk,
          refreshToken: 'rt-old',
          attempts: 1,
          expiresAt: expect.any(Number),
        },
      ]);
      expect(pendingRecord[0].expiresAt).toBeGreaterThan(Date.now() + SEVEN_DAYS_MS - 60_000);
      expect(pendingRecord[0].expiresAt).toBeLessThanOrEqual(Date.now() + SEVEN_DAYS_MS);

      // A second signOut() still failing keeps the record (one more
      // attempt counted) and rejects.
      const again = await rejection(client.signOut());
      expect(again.code).toBe('TEMPORARILY_UNAVAILABLE');
      expect(JSON.parse(store.map.get(PENDING_KEY)!)).toEqual([
        { ...pendingRecord[0], attempts: 2 },
      ]);

      // Once the revoke succeeds the record is wiped and signOut resolves.
      revokeStatus = 200;
      revoked.length = 0;
      await client.signOut();
      expect(revoked).toEqual(['rt-old']);
      expect(store.map.has(PENDING_KEY)).toBe(false);
    });

    it('a pending revoke that fails terminally is dropped', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      await store.set(PENDING_KEY, JSON.stringify([
        pendingEntry(sessionKey, 'rt-pending'),
      ]));
      let revokeCalls = 0;
      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revokeCalls += 1;
          return Promise.resolve(jsonResponse({ error: 'invalid_session_proof' }, 401));
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));
      await client.signOut();
      expect(revokeCalls).toBeGreaterThanOrEqual(1);
      expect(store.map.has(PENDING_KEY)).toBe(false);
    });

    it('construction retries a pending revoke and wipes it on success', async () => {
      const { store, removed } = storeWatchingRemove(PENDING_KEY);
      const sessionKey = generateSessionKeypair();
      await store.set(PENDING_KEY, JSON.stringify([
        pendingEntry(sessionKey, 'rt-pending'),
      ]));
      const revoked: string[] = [];
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revoked.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          return Promise.resolve(new Response(null, { status: 200 }));
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };

      new OpenKeyRN(makeDelegationConfig(store, fetchFn));
      await removed;
      expect(revoked).toEqual(['rt-pending']);
      expect(store.map.has(PENDING_KEY)).toBe(false);
    });

    it('signIn() retries a pending revoke', async () => {
      const { store, removed } = storeWatchingRemove(PENDING_KEY);
      const sessionKey = generateSessionKeypair();
      await store.set(PENDING_KEY, JSON.stringify([
        pendingEntry(sessionKey, 'rt-pending'),
      ]));
      let revokeOk = false;
      const revoked: string[] = [];
      const captured: { parBody?: string } = {};
      const signInFetch = delegationFetch(captured);
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revoked.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          return Promise.resolve(
            revokeOk
              ? new Response(null, { status: 200 })
              : jsonResponse({ error: 'temporarily_unavailable' }, 503),
          );
        }
        return signInFetch(url, init);
      };
      const { openBrowser, opened } = captureOpener();
      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );
      // The construction-time retry fails transiently: the record stays.
      await client.signOut().catch(() => {});
      expect(store.map.has(PENDING_KEY)).toBe(true);

      revokeOk = true;
      revoked.length = 0;
      const signInPromise = client.signIn();
      signInPromise.catch(() => {});
      await opened;
      await removed;
      expect(revoked).toEqual(['rt-pending']);
      expect(store.map.has(PENDING_KEY)).toBe(false);
      await client.signOut();
    });

    it('renew() single-flight treats a subset with and without capabilities/read as one call', async () => {
      const store = memoryStore();
      const sessionKey = await seedSession(store, 'rt-0');
      let renewCalls = 0;
      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          renewCalls += 1;
          return Promise.resolve(
            jsonResponse({
              refresh_token: 'rt-1',
              tinycloud_delegation: {
                verificationMethod: sessionKey.keyId,
                expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                permissions: [CAP_READ, KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));
      const [r1, r2] = await Promise.all([
        client.renew({ permissionsSubset: [KV_PERMISSION] }),
        client.renew({ permissionsSubset: [CAP_READ, KV_PERMISSION] }),
      ]);
      expect(renewCalls).toBe(1);
      expect(r1).toBe(r2);
    });

    it('a subset renew does not narrow the approved set; a later plain renew succeeds', async () => {
      const store = memoryStore();
      const captured: { parBody?: string } = {};
      const signInFetch = delegationFetch(captured);
      const renewBodies: string[] = [];
      let renewCalls = 0;
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          renewCalls += 1;
          renewBodies.push(init!.body!);
          const details = new URLSearchParams(init!.body!).get('authorization_details');
          // Server: the requested subset, or the full approved set.
          const permissions = details
            ? (JSON.parse(details) as { permissions: NativeDelegationPermission[] }[])[0]!.permissions
            : (JSON.parse(
                new URLSearchParams(captured.parBody!).get('authorization_details')!,
              ) as { permissions: NativeDelegationPermission[] }[])[0]!.permissions;
          return Promise.resolve(
            jsonResponse({
              refresh_token: `rt-renew-${renewCalls}`,
              tinycloud_delegation: {
                verificationMethod: sessionKeyIdFromPar(captured.parBody!),
                expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                permissions,
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        return signInFetch(url, init);
      };
      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(captured.parBody!).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;
      const config = makeDelegationConfig(store, fetchFn, { openBrowser });
      config.delegation!.permissions = [KV_PERMISSION, KV_PERMISSION_2];
      const client = new OpenKeyRN(config);

      const signedIn = await client.signIn();
      expect(signedIn.delegation!.permissions).toHaveLength(3);
      const approved = JSON.parse(store.map.get(SESSION_KEY)!).permissions;
      expect(approved).toHaveLength(3);

      const narrowed = await client.renew({ permissionsSubset: [KV_PERMISSION] });
      expect(narrowed.delegation.permissions).toHaveLength(2);
      // The stored approved set is unchanged.
      expect(JSON.parse(store.map.get(SESSION_KEY)!).permissions).toEqual(approved);

      const plain = await client.renew();
      expect(plain.delegation.permissions).toEqual(approved);
      expect(new URLSearchParams(renewBodies[1]!).get('authorization_details')).toBeNull();
      expect(JSON.parse(store.map.get(SESSION_KEY)!).refreshToken).toBe('rt-renew-2');
    });

    // ── Revoke classification: NETWORK, TEMPORARILY_UNAVAILABLE and any
    //    HTTP 5xx (revoke endpoint or discovery) are transient; everything
    //    else, including a 4xx, is terminal ──

    const REVOKE_OUTCOMES: {
      name?: string;
      code: string;
      transient: boolean;
      respond: () => Promise<Response>;
      /** Discovery response; defaults to the metadata. */
      discovery?: () => Promise<Response>;
    }[] = [
      { code: 'NETWORK', transient: true, respond: () => Promise.reject(new Error('offline')) },
      {
        code: 'TEMPORARILY_UNAVAILABLE',
        transient: true,
        respond: () => Promise.resolve(jsonResponse({ error: 'temporarily_unavailable' }, 503)),
      },
      {
        code: 'INVALID_GRANT',
        transient: false,
        respond: () => Promise.resolve(jsonResponse({ error: 'invalid_grant' }, 400)),
      },
      {
        code: 'CONSENT_REQUIRED',
        transient: false,
        respond: () => Promise.resolve(jsonResponse({ error: 'consent_required' }, 400)),
      },
      {
        code: 'ACCESS_DENIED',
        transient: false,
        respond: () => Promise.resolve(jsonResponse({ error: 'access_denied' }, 403)),
      },
      {
        code: 'SPACE_UNAVAILABLE',
        transient: false,
        respond: () => Promise.resolve(jsonResponse({ error: 'space_unavailable' }, 409)),
      },
      {
        name: 'SERVER 500',
        code: 'SERVER',
        transient: true,
        respond: () => Promise.resolve(jsonResponse({ error: 'server_error' }, 500)),
      },
      {
        name: 'SERVER 502 (non-JSON)',
        code: 'SERVER',
        transient: true,
        respond: () => Promise.resolve(new Response('bad gateway', { status: 502 })),
      },
      {
        name: 'SERVER 429',
        code: 'SERVER',
        transient: true,
        respond: () => Promise.resolve(jsonResponse({ error: 'slow_down' }, 429)),
      },
      {
        name: 'SERVER 400',
        code: 'SERVER',
        transient: false,
        respond: () => Promise.resolve(jsonResponse({ error: 'invalid_request' }, 400)),
      },
      {
        name: 'discovery 503',
        code: 'SERVER',
        transient: true,
        respond: () => Promise.reject(new Error('revoke must not be reached')),
        discovery: () => Promise.resolve(new Response(null, { status: 503 })),
      },
      {
        name: 'discovery 404',
        code: 'SERVER',
        transient: false,
        respond: () => Promise.reject(new Error('revoke must not be reached')),
        discovery: () => Promise.resolve(new Response(null, { status: 404 })),
      },
    ];

    function revokeFetch(outcome: (typeof REVOKE_OUTCOMES)[number]): NativeFetch {
      return (url: string) => {
        if (url.includes('/.well-known/')) {
          return outcome.discovery
            ? outcome.discovery()
            : Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) return outcome.respond();
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
    }

    for (const outcome of REVOKE_OUTCOMES) {
      const label = outcome.name ?? outcome.code;
      const verdict = outcome.transient
        ? 'keeps a pending revoke and rejects'
        : 'wipes and resolves';

      it(`signOut() on a ${label} revoke failure ${verdict}`, async () => {
        const store = memoryStore();
        const sessionKey = await seedSession(store, 'rt-live');
        const client = new OpenKeyRN(
          makeDelegationConfig(store, revokeFetch(outcome)),
        );

        if (outcome.transient) {
          const thrown = await rejection(client.signOut());
          expect(thrown.code).toBe(outcome.code);
          expect(JSON.parse(store.map.get(PENDING_KEY)!)).toEqual([
            {
              privateJwk: sessionKey.privateJwk,
              refreshToken: 'rt-live',
              attempts: 1,
              expiresAt: expect.any(Number),
            },
          ]);
        } else {
          await client.signOut();
          expect(store.map.has(PENDING_KEY)).toBe(false);
        }
        expect(store.map.has(SESSION_KEY)).toBe(false);
      });

      it(`a pending revoke retried on a ${label} failure ${
        outcome.transient ? 'is kept' : 'is dropped'
      }`, async () => {
        const store = memoryStore();
        const sessionKey = generateSessionKeypair();
        const pendingRecord = [pendingEntry(sessionKey, 'rt-pending')];
        await store.set(PENDING_KEY, JSON.stringify(pendingRecord));
        const client = new OpenKeyRN(
          makeDelegationConfig(store, revokeFetch(outcome)),
        );

        // No live session: signOut() only retries the pending revoke.
        if (outcome.transient) {
          const thrown = await rejection(client.signOut());
          expect(thrown.code).toBe(outcome.code);
          expect(JSON.parse(store.map.get(PENDING_KEY)!)).toEqual([
            { ...pendingRecord[0], attempts: 2 },
          ]);
        } else {
          await client.signOut();
          expect(store.map.has(PENDING_KEY)).toBe(false);
        }
      });
    }

    // ── Generation / session binding (round 4) ──

    it('a signOut() that completes during discovery invalidates the signIn()', async () => {
      const store = memoryStore();
      const { promise: discoveryReached, resolve: reachedDiscovery } =
        Promise.withResolvers<void>();
      const { promise: discoveryGate, resolve: releaseDiscovery } =
        Promise.withResolvers<void>();
      const captured: { parBody?: string } = {};
      const inner = delegationFetch(captured);
      const fetchFn: NativeFetch = async (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          reachedDiscovery();
          await discoveryGate;
        }
        return inner(url, init);
      };
      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(captured.parBody!).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;
      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );

      const signInPromise = client.signIn();
      signInPromise.catch(() => {});
      await discoveryReached;
      await client.signOut();
      releaseDiscovery();

      const thrown = await rejection(signInPromise);
      expect(thrown.code).toBe('NOT_SIGNED_IN');
      expect(openBrowser).not.toHaveBeenCalled();
      expect(store.map.has(SESSION_KEY)).toBe(false);
    });

    it('a storage read overtaken by signOut() never repopulates the session cache', async () => {
      const base = memoryStore();
      const sessionKey = await seedSession(base, 'rt-old');
      const { promise: readReached, resolve: reachedRead } =
        Promise.withResolvers<void>();
      const { promise: readGate, resolve: releaseRead } =
        Promise.withResolvers<void>();
      let gateNextSessionRead = true;
      const store: OpenKeySecureStore = {
        ...base,
        get: async (key) => {
          // The value is read when the call starts; it lands later.
          const value = base.map.get(key) ?? null;
          if (key === SESSION_KEY && gateNextSessionRead) {
            gateNextSessionRead = false;
            reachedRead();
            await readGate;
          }
          return value;
        },
      };
      let renewCalls = 0;
      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          renewCalls += 1;
          return Promise.resolve(
            jsonResponse({
              refresh_token: 'rt-new',
              tinycloud_delegation: {
                verificationMethod: sessionKey.keyId,
                expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
                permissions: [KV_PERMISSION],
                tinycloudHost: TC_HOST,
              },
            }),
          );
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          return Promise.resolve(new Response(null, { status: 200 }));
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));

      const first = client.renew();
      first.catch(() => {});
      await readReached;
      await client.signOut();
      releaseRead();

      expect((await rejection(first)).code).toBe('NOT_SIGNED_IN');
      // A later renew() must not use a session loaded before the sign-out.
      expect((await rejection(client.renew())).code).toBe('NOT_SIGNED_IN');
      expect(renewCalls).toBe(0);
      expect(base.map.has(SESSION_KEY)).toBe(false);
    });

    /**
     * Fetch for "renew of the stored session A is in flight while signIn()
     * stores session B": the first renew is held until `release`, then
     * answered by `firstRenew`; later renews succeed for session B.
     */
    function renewRaceFetch(firstRenew: () => Response) {
      const captured: { parBody?: string } = {};
      const inner = delegationFetch(captured);
      const reached = Promise.withResolvers<void>();
      const gate = Promise.withResolvers<void>();
      const renewTokens: string[] = [];
      const revoked: string[] = [];
      const fetchFn: NativeFetch = async (url: string, init?: NativeFetchInit) => {
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          renewTokens.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          if (renewTokens.length === 1) {
            reached.resolve();
            await gate.promise;
            return firstRenew();
          }
          return jsonResponse({
            refresh_token: 'rt-b-2',
            tinycloud_delegation: {
              ...delegationPayload(captured.parBody!),
            },
          });
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revoked.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          return new Response(null, { status: 200 });
        }
        return inner(url, init);
      };
      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(captured.parBody!).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;
      return {
        fetchFn,
        openBrowser,
        renewReached: reached.promise,
        releaseRenew: () => gate.resolve(),
        renewTokens,
        revoked,
      };
    }

    it('a terminal renew of an older session leaves a newer signed-in session alone', async () => {
      const store = memoryStore();
      await seedSession(store, 'rt-a');
      const race = renewRaceFetch(() => jsonResponse({ error: 'invalid_grant' }, 400));
      const client = new OpenKeyRN(
        makeDelegationConfig(store, race.fetchFn, { openBrowser: race.openBrowser }),
      );

      const oldRenew = client.renew();
      oldRenew.catch(() => {});
      await race.renewReached;
      await client.signIn(); // stores session B
      const sessionB = store.map.get(SESSION_KEY)!;
      expect(JSON.parse(sessionB).refreshToken).toBe('nat-refresh-1');

      race.releaseRenew();
      expect((await rejection(oldRenew)).code).toBe('INVALID_GRANT');
      // Session A's terminal outcome did not wipe session B.
      expect(store.map.get(SESSION_KEY)).toBe(sessionB);
      const renewed = await client.renew();
      expect(race.renewTokens).toEqual(['rt-a', 'nat-refresh-1']);
      expect(renewed.refreshToken).toBe('rt-b-2');
    });

    it('a renew of an older session never overwrites a newer signed-in session', async () => {
      const store = memoryStore();
      const sessionA = await seedSession(store, 'rt-a');
      const race = renewRaceFetch(() =>
        jsonResponse({
          refresh_token: 'rt-a-rotated',
          tinycloud_delegation: {
            verificationMethod: sessionA.keyId,
            expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
            permissions: [KV_PERMISSION],
            tinycloudHost: TC_HOST,
          },
        }),
      );
      const client = new OpenKeyRN(
        makeDelegationConfig(store, race.fetchFn, { openBrowser: race.openBrowser }),
      );

      const oldRenew = client.renew();
      oldRenew.catch(() => {});
      await race.renewReached;
      await client.signIn(); // stores session B
      const sessionB = store.map.get(SESSION_KEY)!;

      race.releaseRenew();
      const thrown = await rejection(oldRenew);
      expect(thrown.code).toBe('NOT_SIGNED_IN');
      expect(thrown.rotatedRefreshToken).toBe('rt-a-rotated');
      // Session B is intact and A's orphaned rotated grant was revoked.
      expect(store.map.get(SESSION_KEY)).toBe(sessionB);
      expect(race.revoked).toEqual(['rt-a-rotated']);
    });

    // ── Round 5: bounded pending revoke, discovery retry, signIn/renew
    //    isolation ──

    it('a pending revoke past its refresh-token expiry is dropped without a revoke', async () => {
      const store = memoryStore();
      const sessionKey = generateSessionKeypair();
      await store.set(PENDING_KEY, JSON.stringify([
        pendingEntry(sessionKey, 'rt-expired', { expiresAt: Date.now() - 1 }),
      ]));
      let revokeCalls = 0;
      const fetchFn: NativeFetch = (url: string) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revokeCalls += 1;
          return Promise.resolve(jsonResponse({ error: 'temporarily_unavailable' }, 503));
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));
      await client.signOut();
      expect(revokeCalls).toBe(0);
      expect(store.map.has(PENDING_KEY)).toBe(false);
    });

    it('a pending revoke is dropped after its 20th attempt', async () => {
      const store = memoryStore();
      const keyA = generateSessionKeypair();
      const keyB = generateSessionKeypair();
      await store.set(PENDING_KEY, JSON.stringify([
        pendingEntry(keyA, 'rt-at-19', { attempts: 19 }),
        pendingEntry(keyB, 'rt-at-5', { attempts: 5 }),
      ]));
      const revoked: string[] = [];
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.includes('/.well-known/')) {
          return Promise.resolve(jsonResponse(METADATA));
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revoked.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          return Promise.resolve(jsonResponse({ error: 'server_error' }, 500));
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
      };
      const client = new OpenKeyRN(makeDelegationConfig(store, fetchFn));

      // Both were attempted; the transient failure still rejects signOut().
      const thrown = await rejection(client.signOut());
      expect(thrown.code).toBe('SERVER');
      expect(thrown.status).toBe(500);
      expect(revoked).toEqual(['rt-at-19', 'rt-at-5']);
      // The 20th attempt dropped its entry; the other counts up.
      const remaining = JSON.parse(store.map.get(PENDING_KEY)!);
      expect(remaining).toHaveLength(1);
      expect(remaining[0].refreshToken).toBe('rt-at-5');
      expect(remaining[0].attempts).toBe(6);
    });

    it('a pending revoke expires with the grant when it ends before the 7-day TTL', async () => {
      const store = memoryStore();
      const captured: { parBody?: string } = {};
      const signInFetch = delegationFetch(captured);
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          return Promise.reject(new Error('offline'));
        }
        return signInFetch(url, init);
      };
      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(captured.parBody!).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;
      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );

      const result = await client.signIn();
      // delegationPayload: renewableUntil = now + 1 day; the grant's
      // absolute expiry is 300 s later.
      const grantEnd = Date.parse(String(result.delegation!.renewableUntil)) + 300_000;
      const session = JSON.parse(store.map.get(SESSION_KEY)!);
      expect(session.grantExpiresAt).toBe(grantEnd);
      expect(session.refreshTokenExpiresAt).toBe(grantEnd);

      expect((await rejection(client.signOut())).code).toBe('NETWORK');
      const [entry] = JSON.parse(store.map.get(PENDING_KEY)!);
      expect(entry.refreshToken).toBe('nat-refresh-1');
      expect(entry.attempts).toBe(1);
      expect(entry.expiresAt).toBe(grantEnd);
    });

    it('an offline launch with a pending revoke recovers once the network is back', async () => {
      const store = memoryStore();
      const pendingKey = generateSessionKeypair();
      await store.set(PENDING_KEY, JSON.stringify([
        pendingEntry(pendingKey, 'rt-pending'),
      ]));
      let online = false;
      let discoveryCalls = 0;
      const revoked: string[] = [];
      const captured: { parBody?: string } = {};
      const signInFetch = delegationFetch(captured);
      const fetchFn: NativeFetch = (url: string, init?: NativeFetchInit) => {
        if (!online) return Promise.reject(new Error('offline'));
        if (url.includes('/.well-known/')) discoveryCalls += 1;
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          return Promise.resolve(
            jsonResponse({
              refresh_token: 'rt-renewed',
              tinycloud_delegation: delegationPayload(captured.parBody!),
            }),
          );
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revoked.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          return Promise.resolve(new Response(null, { status: 200 }));
        }
        return signInFetch(url, init);
      };
      const openBrowser = mock(async (): Promise<BrowserResult | void> => {
        const state = new URLSearchParams(captured.parBody!).get('state')!;
        return { type: 'success', url: callbackUrl(state) };
      }) as BrowserOpener;
      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );

      // Offline: the launch-time retry fails at discovery; nothing cached.
      expect((await rejection(client.signOut())).code).toBe('NETWORK');
      expect(JSON.parse(store.map.get(PENDING_KEY)!)[0].attempts).toBe(2);

      online = true;
      const signedIn = await client.signIn();
      expect(signedIn.refreshToken).toBe('nat-refresh-1');
      const renewed = await client.renew();
      expect(renewed.refreshToken).toBe('rt-renewed');
      await client.signOut();

      expect(discoveryCalls).toBe(1); // retried after the offline failure, then cached
      expect(revoked).toContain('rt-pending');
      expect(revoked).toContain('rt-renewed');
      expect(store.map.has(PENDING_KEY)).toBe(false);
      expect(store.map.has(SESSION_KEY)).toBe(false);
    });

    it('a cancelled signIn() does not disturb an in-flight renew of the stored session', async () => {
      const store = memoryStore();
      const sessionA = await seedSession(store, 'rt-a');
      const { promise: renewReached, resolve: reachedRenew } =
        Promise.withResolvers<void>();
      const { promise: renewGate, resolve: releaseRenew } =
        Promise.withResolvers<void>();
      const revoked: string[] = [];
      const captured: { parBody?: string } = {};
      const signInFetch = delegationFetch(captured);
      const fetchFn: NativeFetch = async (url: string, init?: NativeFetchInit) => {
        if (url.endsWith('/oauth2/tinycloud/renew')) {
          reachedRenew();
          await renewGate;
          return jsonResponse({
            refresh_token: 'rt-a-rotated',
            tinycloud_delegation: {
              verificationMethod: sessionA.keyId,
              expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
              permissions: [KV_PERMISSION],
              tinycloudHost: TC_HOST,
            },
          });
        }
        if (url.endsWith('/oauth2/tinycloud/revoke')) {
          revoked.push(new URLSearchParams(init!.body!).get('refresh_token')!);
          return new Response(null, { status: 200 });
        }
        return signInFetch(url, init);
      };
      const openBrowser = mock(async () => ({ type: 'cancel' as const })) as BrowserOpener;
      const client = new OpenKeyRN(
        makeDelegationConfig(store, fetchFn, { openBrowser }),
      );

      const renewPromise = client.renew();
      await renewReached;
      let cancelled: unknown;
      try {
        await client.signIn();
        expect(true).toBe(false);
      } catch (error) {
        cancelled = error;
      }
      expect((cancelled as { code: string }).code).toBe('USER_CANCELLED');
      releaseRenew();

      // The renew of session A completes and persists its rotated token.
      expect((await renewPromise).refreshToken).toBe('rt-a-rotated');
      const record = JSON.parse(store.map.get(SESSION_KEY)!);
      expect(record.privateJwk.x).toBe(sessionA.publicJwk.x);
      expect(record.refreshToken).toBe('rt-a-rotated');
      expect(revoked).toEqual([]);
    });

  });

  describe('flow timers', () => {
    it('clears the sign-in timeout on every settlement path', async () => {
      const created: unknown[] = [];
      const cleared: unknown[] = [];
      const realSetTimeout = globalThis.setTimeout;
      const realClearTimeout = globalThis.clearTimeout;
      globalThis.setTimeout = ((fn: () => void, ms?: number) => {
        const id = realSetTimeout(fn, ms);
        created.push(id);
        return id;
      }) as typeof setTimeout;
      globalThis.clearTimeout = ((id?: unknown) => {
        cleared.push(id);
        realClearTimeout(id as Parameters<typeof clearTimeout>[0]);
      }) as typeof clearTimeout;

      try {
        // Path 1: cancel result.
        mockFetch(() => Promise.resolve(jsonResponse(TOKEN_RESPONSE)));
        const cancelled = new OpenKeyRN(
          makeConfig({
            openBrowser: mock(async (): Promise<BrowserResult | void> => ({
              type: 'cancel',
            })) as BrowserOpener,
          }),
        );
        await expect(cancelled.signIn()).rejects.toMatchObject({
          code: 'USER_CANCELLED',
        });

        // Path 2: success result → callback → exchange.
        const succeeded = new OpenKeyRN(
          makeConfig({
            openBrowser: mock(
              async (url: string): Promise<BrowserResult | void> => {
                const state = new URL(url).searchParams.get('state')!;
                return { type: 'success', url: callbackUrl(state) };
              },
            ) as BrowserOpener,
          }),
        );
        await succeeded.signIn();

        // Path 3: deep-link handleCallback.
        const { openBrowser, opened } = captureOpener();
        const deepLinked = new OpenKeyRN(makeConfig({ openBrowser }));
        const signInPromise = deepLinked.signIn();
        const state = new URL(await opened).searchParams.get('state')!;
        deepLinked.handleCallback(callbackUrl(state));
        await signInPromise;

        // Path 4: error= callback.
        const denied = new OpenKeyRN(
          makeConfig({
            openBrowser: mock(
              async (url: string): Promise<BrowserResult | void> => {
                const s = new URL(url).searchParams.get('state')!;
                return {
                  type: 'success',
                  url: callbackUrl(s, { error: 'access_denied' }),
                };
              },
            ) as BrowserOpener,
          }),
        );
        await expect(denied.signIn()).rejects.toMatchObject({
          code: 'ACCESS_DENIED',
        });

        // Every timer created was cleared — none left pending.
        expect(created.length).toBeGreaterThanOrEqual(4);
        for (const id of created) {
          expect(cleared).toContain(id);
        }
      } finally {
        globalThis.setTimeout = realSetTimeout;
        globalThis.clearTimeout = realClearTimeout;
      }
    });
  });
});
