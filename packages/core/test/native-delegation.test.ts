/**
 * Unit tests for the native TinyCloud delegation module (TC-774 S1).
 *
 * Server endpoints do not exist yet, so every client is exercised through
 * an injected mock fetch. The proof JWS is verified with `jose` as a real
 * EdDSA round-trip.
 */

import { describe, expect, it } from 'bun:test';
import { importJWK, compactVerify, decodeProtectedHeader, decodeJwt } from 'jose';
import { ed25519 } from '@noble/curves/ed25519';

import {
  OpenKeyNativeError,
  SESSION_PROOF_HEADER,
  SESSION_PROOF_TYP,
  generateNonce,
  generateState,
  generateCodeVerifier,
  generateCodeChallenge,
  sha256,
  base64UrlDecode,
  sessionDidForPublicKey,
  generateSessionKeypair,
  sessionKeypairFromJwk,
  discoveryUrlForIssuer,
  discoverOpenKeyServer,
  buildAuthorizationDetails,
  buildParRequest,
  sendParRequest,
  buildNativeAuthorizeUrl,
  parseNativeCallback,
  signSessionProof,
  isPermissionSubset,
  validateTinyCloudDelegation,
  exchangeDelegationCode,
  renewDelegation,
  revokeDelegation,
  type NativeFetch,
  type NativeFetchResponse,
  type NativeDelegationPermission,
  type OpenKeyServerMetadata,
} from '../src/index';

const ISSUER = 'https://api.openkey.so/api/auth';
const ORIGIN = 'https://api.openkey.so';
const CLIENT_ID = 'native-app';
const REDIRECT_URI = 'xyz.tinycloud.exo://openkey/callback';

const METADATA = {
  issuer: ISSUER,
  authorization_endpoint: `${ORIGIN}/api/auth/oauth2/authorize`,
  token_endpoint: `${ORIGIN}/api/auth/oauth2/token`,
  pushed_authorization_request_endpoint: `${ORIGIN}/api/auth/oauth2/par`,
  tinycloud_delegation_renew_endpoint: `${ORIGIN}/api/auth/oauth2/tinycloud/renew`,
  tinycloud_delegation_revocation_endpoint: `${ORIGIN}/api/auth/oauth2/tinycloud/revoke`,
};

const SERVER_METADATA: OpenKeyServerMetadata = {
  issuer: ISSUER,
  origin: ORIGIN,
  authorizationEndpoint: METADATA.authorization_endpoint,
  tokenEndpoint: METADATA.token_endpoint,
  pushedAuthorizationRequestEndpoint:
    METADATA.pushed_authorization_request_endpoint,
  tinycloudDelegationRenewEndpoint:
    METADATA.tinycloud_delegation_renew_endpoint,
  tinycloudDelegationRevocationEndpoint:
    METADATA.tinycloud_delegation_revocation_endpoint,
};

function jsonResponse(body: unknown, status = 200): NativeFetchResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  };
}

/** A mock fetch that asserts URL/method and records the request. */
function mockFetch(
  handler: (url: string, init: RequestInit) => unknown | NativeFetchResponse,
): { fetchFn: NativeFetch; calls: { url: string; init: RequestInit }[] } {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchFn: NativeFetch = async (url, init) => {
    calls.push({ url, init: init as RequestInit });
    const result = handler(url, init as RequestInit);
    return 'json' in (result as NativeFetchResponse)
      ? (result as NativeFetchResponse)
      : jsonResponse(result);
  };
  return { fetchFn, calls };
}

const PERMISSIONS: NativeDelegationPermission[] = [
  {
    service: 'kv',
    space: 'applications',
    path: 'xyz.tinycloud.tinychat/threads/',
    actions: ['get', 'put', 'list', 'del', 'metadata'],
  },
  {
    service: 'sql',
    space: 'applications',
    path: 'xyz.tinycloud.tinychat/threads',
    actions: ['read', 'write', 'schema'],
  },
];

/** Assert `fn` throws an OpenKeyNativeError with the given code. */
function expectCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(OpenKeyNativeError);
    expect((error as OpenKeyNativeError).code).toBe(code);
    return;
  }
  expect.unreachable();
}

const FUTURE = new Date(Date.now() + 3_600_000).toISOString();

function delegationFor(
  keyId: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    version: 1,
    grantId: 'grant-1',
    verificationMethod: keyId,
    expiresAt: FUTURE,
    permissions: PERMISSIONS,
    tinycloudHost: 'https://tee.node.tinycloud.xyz',
    hosting: 'existing',
    ...overrides,
  };
}

// ======= Discovery =======

describe('discovery', () => {
  it('builds the RFC 8414 URL by inserting the prefix before the issuer path', () => {
    expect(discoveryUrlForIssuer(ISSUER)).toBe(
      `${ORIGIN}/.well-known/oauth-authorization-server/api/auth`,
    );
  });

  it('accepts valid metadata and keeps origin and issuer separate', async () => {
    const { fetchFn, calls } = mockFetch(() => METADATA);
    const meta = await discoverOpenKeyServer(ISSUER, fetchFn);
    expect(calls[0]!.url).toBe(discoveryUrlForIssuer(ISSUER));
    expect(meta.issuer).toBe(ISSUER);
    expect(meta.origin).toBe(ORIGIN);
    expect(meta.pushedAuthorizationRequestEndpoint).toBe(
      METADATA.pushed_authorization_request_endpoint,
    );
    expect(meta.tinycloudDelegationRenewEndpoint).toBe(
      METADATA.tinycloud_delegation_renew_endpoint,
    );
    expect(meta.tinycloudDelegationRevocationEndpoint).toBe(
      METADATA.tinycloud_delegation_revocation_endpoint,
    );
  });

  it('rejects an issuer mismatch', async () => {
    const { fetchFn } = mockFetch(() => ({
      ...METADATA,
      issuer: 'https://attacker.example.com/api/auth',
    }));
    try {
      await discoverOpenKeyServer(ISSUER, fetchFn);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(OpenKeyNativeError);
      expect((error as OpenKeyNativeError).code).toBe('ISSUER_MISMATCH');
    }
  });

  it('rejects http issuers', async () => {
    const { fetchFn } = mockFetch(() => METADATA);
    await expect(
      discoverOpenKeyServer('http://api.openkey.so/api/auth', fetchFn),
    ).rejects.toMatchObject({ code: 'SERVER' });
  });

  it('rejects endpoints off the issuer origin', async () => {
    const { fetchFn } = mockFetch(() => ({
      ...METADATA,
      token_endpoint: 'https://evil.example.com/api/auth/oauth2/token',
    }));
    await expect(discoverOpenKeyServer(ISSUER, fetchFn)).rejects.toMatchObject(
      { code: 'SERVER' },
    );
  });

  it('rejects metadata missing the delegation endpoints', async () => {
    const { fetchFn } = mockFetch(() => ({
      issuer: ISSUER,
      authorization_endpoint: METADATA.authorization_endpoint,
      token_endpoint: METADATA.token_endpoint,
      pushed_authorization_request_endpoint:
        METADATA.pushed_authorization_request_endpoint,
    }));
    await expect(discoverOpenKeyServer(ISSUER, fetchFn)).rejects.toMatchObject(
      { code: 'SERVER' },
    );
  });

  it('maps fetch failures to NETWORK', async () => {
    const failing: NativeFetch = () => Promise.reject(new Error('offline'));
    await expect(discoverOpenKeyServer(ISSUER, failing)).rejects.toMatchObject(
      { code: 'NETWORK' },
    );
  });
});

// ======= PKCE / state / nonce =======

describe('pkce and state', () => {
  it('generates a 43-char verifier whose S256 challenge is b64url(sha256(verifier))', async () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toHaveLength(43);
    const challenge = await generateCodeChallenge(verifier);
    const expected = Buffer.from(await sha256(verifier)).toString('base64url');
    expect(challenge).toBe(expected);
    // RFC 7636 test vector
    expect(
      await generateCodeChallenge(
        'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      ),
    ).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('generates distinct 22-char states', () => {
    const a = generateState();
    const b = generateState();
    expect(a).toHaveLength(22);
    expect(b).toHaveLength(22);
    expect(a).not.toBe(b);
  });

  it('generates alphanumeric nonces (siwe_nonce grammar)', () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9]{32}$/);
    expect(generateNonce(48)).toMatch(/^[A-Za-z0-9]{48}$/);
  });
});

// ======= Session keys =======

describe('session keys', () => {
  it('derives the multibase did:key from the Ed25519 public key', () => {
    // RFC 8032 test key: secret all-zero is not valid via derivation, so
    // pin the known did:key for a zero public key instead.
    const did = sessionDidForPublicKey(new Uint8Array(32));
    expect(did).toBe(
      'did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP',
    );
  });

  it('generates a keypair with did, fragment keyId and matching JWKs', () => {
    const key = generateSessionKeypair();
    expect(key.did).toMatch(/^did:key:z6Mk/);
    expect(key.keyId).toBe(`${key.did}#${key.did.slice(8)}`);
    expect(key.publicJwk).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
      kid: key.keyId,
    });
    expect(base64UrlDecode(key.publicJwk.x)).toHaveLength(32);
    expect(base64UrlDecode(key.privateJwk.d)).toHaveLength(32);
    // x is the public key for d
    expect(
      Buffer.from(
        ed25519.getPublicKey(base64UrlDecode(key.privateJwk.d)),
      ).toString('base64url'),
    ).toBe(key.publicJwk.x);
  });

  it('restores a keypair from its private JWK and rejects mismatched x', () => {
    const key = generateSessionKeypair();
    const restored = sessionKeypairFromJwk(key.privateJwk);
    expect(restored.did).toBe(key.did);
    expect(restored.keyId).toBe(key.keyId);
    const other = generateSessionKeypair();
    expect(() =>
      sessionKeypairFromJwk({ ...key.privateJwk, x: other.publicJwk.x }),
    ).toThrow(OpenKeyNativeError);
  });
});

// ======= authorization_details / PAR =======

describe('PAR', () => {
  it('builds authorization_details of type tinycloud_delegation', () => {
    const key = generateSessionKeypair();
    const details = buildAuthorizationDetails({
      sessionKey: key,
      permissions: PERMISSIONS,
      ttlSeconds: 3600,
      siweNonce: 'abc123nonce',
    });
    expect(details).toHaveLength(1);
    expect(details[0]).toEqual({
      type: 'tinycloud_delegation',
      session_key: key.publicJwk,
      permissions: PERMISSIONS,
      ttl_seconds: 3600,
      siwe_nonce: 'abc123nonce',
    });
    // public-only JWK on the wire
    expect(details[0]!.session_key).not.toHaveProperty('d');
  });

  it('builds the form-encoded PAR body', () => {
    const key = generateSessionKeypair();
    const { body, contentType } = buildParRequest({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      state: 'state-1',
      codeChallenge: 'challenge-1',
      sessionKey: key,
      permissions: PERMISSIONS,
    });
    expect(contentType).toBe('application/x-www-form-urlencoded');
    const form = new URLSearchParams(body);
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('response_type')).toBe('code');
    expect(form.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(form.get('state')).toBe('state-1');
    expect(form.get('code_challenge')).toBe('challenge-1');
    expect(form.get('code_challenge_method')).toBe('S256');
    expect(form.get('scope')).toBe(
      'openid offline_access tinycloud:delegation',
    );
    const details = JSON.parse(form.get('authorization_details')!);
    expect(details[0].type).toBe('tinycloud_delegation');
    expect(details[0].session_key.x).toBe(key.publicJwk.x);
  });

  it('POSTs PAR and returns request_uri', async () => {
    const key = generateSessionKeypair();
    const { fetchFn, calls } = mockFetch(() =>
      jsonResponse(
        {
          request_uri: 'urn:ietf:params:oauth:request_uri:req-1',
          expires_in: 90,
        },
        201,
      ),
    );
    const result = await sendParRequest(
      SERVER_METADATA,
      {
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        state: 's',
        codeChallenge: 'c',
        sessionKey: key,
        permissions: PERMISSIONS,
      },
      fetchFn,
    );
    expect(calls[0]!.url).toBe(SERVER_METADATA.pushedAuthorizationRequestEndpoint);
    expect(calls[0]!.init.method).toBe('POST');
    expect(result.requestUri).toBe('urn:ietf:params:oauth:request_uri:req-1');
    expect(result.expiresIn).toBe(90);
  });
});

// ======= Authorize URL =======

describe('authorize url', () => {
  it('builds authorization_endpoint?client_id&request_uri', () => {
    const url = buildNativeAuthorizeUrl({
      authorizationEndpoint: SERVER_METADATA.authorizationEndpoint,
      clientId: CLIENT_ID,
      requestUri: 'urn:ietf:params:oauth:request_uri:req-1',
    });
    const parsed = new URL(url);
    expect(parsed.origin + parsed.pathname).toBe(
      SERVER_METADATA.authorizationEndpoint,
    );
    expect(parsed.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(parsed.searchParams.get('request_uri')).toBe(
      'urn:ietf:params:oauth:request_uri:req-1',
    );
    expect([...parsed.searchParams.keys()].sort()).toEqual([
      'client_id',
      'request_uri',
    ]);
  });
});

// ======= Callback =======

describe('callback', () => {
  const base = 'xyz.tinycloud.exo://openkey/callback';
  const opts = { expectedState: 'state-1', issuer: ISSUER };

  it('returns code and state on success', () => {
    const result = parseNativeCallback({
      url: `${base}?code=code-1&state=state-1&iss=${encodeURIComponent(ISSUER)}`,
      ...opts,
    });
    expect(result.code).toBe('code-1');
    expect(result.state).toBe('state-1');
    expect(result.iss).toBe(ISSUER);
  });

  it('maps error=access_denied to ACCESS_DENIED', () => {
    expectCode(
      () =>
        parseNativeCallback({
          url: `${base}?error=access_denied&state=state-1&iss=${encodeURIComponent(ISSUER)}`,
          ...opts,
        }),
      'ACCESS_DENIED',
    );
  });

  it('maps a state mismatch to STATE_MISMATCH, including on error redirects', () => {
    expectCode(
      () =>
        parseNativeCallback({
          url: `${base}?code=code-1&state=wrong&iss=${encodeURIComponent(ISSUER)}`,
          ...opts,
        }),
      'STATE_MISMATCH',
    );
    expectCode(
      () =>
        parseNativeCallback({
          url: `${base}?error=access_denied&state=wrong&iss=${encodeURIComponent(ISSUER)}`,
          ...opts,
        }),
      'STATE_MISMATCH',
    );
  });

  it('rejects an iss mismatch', () => {
    expectCode(
      () =>
        parseNativeCallback({
          url: `${base}?code=code-1&state=state-1&iss=${encodeURIComponent('https://evil.example.com/api/auth')}`,
          ...opts,
        }),
      'ISSUER_MISMATCH',
    );
  });

  it('maps consent_required and unknown errors', () => {
    expectCode(
      () =>
        parseNativeCallback({
          url: `${base}?error=consent_required&state=state-1&iss=${encodeURIComponent(ISSUER)}`,
          ...opts,
        }),
      'CONSENT_REQUIRED',
    );
    expectCode(
      () =>
        parseNativeCallback({
          url: `${base}?error=server_error&state=state-1&iss=${encodeURIComponent(ISSUER)}`,
          ...opts,
        }),
      'SERVER',
    );
  });

  it('rejects a callback with neither code nor error', () => {
    expectCode(
      () =>
        parseNativeCallback({
          url: `${base}?state=state-1&iss=${encodeURIComponent(ISSUER)}`,
          ...opts,
        }),
      'SERVER',
    );
  });

  it('rejects a missing iss', () => {
    expectCode(
      () =>
        parseNativeCallback({
          url: `${base}?code=code-1&state=state-1`,
          ...opts,
        }),
      'ISSUER_MISMATCH',
    );
  });
});

// ======= Session proof =======

describe('session proof', () => {
  it('round-trips a compact JWS verified with jose', async () => {
    const key = generateSessionKeypair();
    const credential = 'the-authorization-code';
    const jws = await signSessionProof({
      sessionKey: key,
      htm: 'POST',
      htu: METADATA.token_endpoint,
      clientId: CLIENT_ID,
      credential,
      siweNonce: 'nonce1234',
      authorizationDetails: buildAuthorizationDetails({
        sessionKey: key,
        permissions: PERMISSIONS,
      }),
    });

    const parts = jws.split('.');
    expect(parts).toHaveLength(3);

    const header = decodeProtectedHeader(jws);
    expect(header.typ).toBe(SESSION_PROOF_TYP);
    expect(header.alg).toBe('EdDSA');
    expect(header.kid).toBe(key.keyId);

    const jwk = { kty: 'OKP', crv: 'Ed25519', x: key.publicJwk.x };
    const publicKey = await importJWK(jwk, 'EdDSA');
    const { payload } = await compactVerify(jws, publicKey);
    const claims = JSON.parse(new TextDecoder().decode(payload));

    expect(claims.htm).toBe('POST');
    expect(claims.htu).toBe(METADATA.token_endpoint);
    expect(claims.client_id).toBe(CLIENT_ID);
    expect(typeof claims.jti).toBe('string');
    expect(typeof claims.iat).toBe('number');
    expect(claims.siwe_nonce).toBe('nonce1234');
    expect(claims.authorization_details[0].type).toBe('tinycloud_delegation');

    // cred_hash = b64url(sha256(credential))
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(credential),
    );
    expect(claims.cred_hash).toBe(
      Buffer.from(digest).toString('base64url'),
    );

    // A proof signed for a different credential does not verify as valid data.
    const other = await signSessionProof({
      sessionKey: key,
      htm: 'POST',
      htu: METADATA.token_endpoint,
      clientId: CLIENT_ID,
      credential: 'different',
    });
    expect(decodeJwt(other).cred_hash).not.toBe(claims.cred_hash);
  });
});

// ======= Delegation validation =======

describe('validateTinyCloudDelegation', () => {
  const key = generateSessionKeypair();
  const opts = { sessionKey: key, requestedPermissions: PERMISSIONS };

  it('accepts a valid delegation', () => {
    const delegation = validateTinyCloudDelegation(
      delegationFor(key.keyId),
      opts,
    );
    expect(delegation.verificationMethod).toBe(key.keyId);
    expect(delegation.tinycloudHost).toBe('https://tee.node.tinycloud.xyz');
  });

  it('rejects a foreign verificationMethod', () => {
    const other = generateSessionKeypair();
    expectCode(
      () => validateTinyCloudDelegation(delegationFor(other.keyId), opts),
      'SERVER',
    );
  });

  it('rejects an expired expiresAt', () => {
    expectCode(
      () =>
        validateTinyCloudDelegation(
          delegationFor(key.keyId, {
            expiresAt: new Date(Date.now() - 1000).toISOString(),
          }),
          opts,
        ),
      'SERVER',
    );
  });

  it('rejects a permission superset (extra action, wider path, extra service)', () => {
    expectCode(
      () =>
        validateTinyCloudDelegation(
          delegationFor(key.keyId, {
            permissions: [
              { ...PERMISSIONS[0]!, actions: [...PERMISSIONS[0]!.actions, 'admin'] },
            ],
          }),
          opts,
        ),
      'SERVER',
    );
    expectCode(
      () =>
        validateTinyCloudDelegation(
          delegationFor(key.keyId, {
            permissions: [
              { service: 'kv', space: 'applications', actions: ['get'] },
            ],
          }),
          opts,
        ),
      'SERVER',
    );
    expectCode(
      () =>
        validateTinyCloudDelegation(
          delegationFor(key.keyId, {
            permissions: [
              ...PERMISSIONS,
              {
                service: 'encryption',
                space: 'applications',
                path: 'x',
                actions: ['read'],
              },
            ],
          }),
          opts,
        ),
      'SERVER',
    );
  });

  it('accepts a narrowed subset', () => {
    expect(() =>
      validateTinyCloudDelegation(
        delegationFor(key.keyId, {
          permissions: [
            {
              service: 'kv',
              space: 'applications',
              path: 'xyz.tinycloud.tinychat/threads/abc',
              actions: ['get'],
            },
          ],
        }),
        opts,
      ),
    ).not.toThrow();
  });

  it('rejects a missing or non-https tinycloudHost', () => {
    expectCode(
      () =>
        validateTinyCloudDelegation(
          delegationFor(key.keyId, { tinycloudHost: undefined }),
          opts,
        ),
      'SERVER',
    );
    expectCode(
      () =>
        validateTinyCloudDelegation(
          delegationFor(key.keyId, { tinycloudHost: 'http://evil.example.com' }),
          opts,
        ),
      'SERVER',
    );
  });
});

// ======= Endpoint clients =======

describe('endpoint clients', () => {
  const key = generateSessionKeypair();

  it('exchangeDelegationCode posts the form with OpenKey-Session-Proof', async () => {
    const { fetchFn, calls } = mockFetch(() =>
      jsonResponse({
        access_token: 'at-1',
        refresh_token: 'rt-1',
        expires_in: 3600,
        token_type: 'Bearer',
        tinycloud_delegation: delegationFor(key.keyId),
      }),
    );
    const result = await exchangeDelegationCode({
      metadata: SERVER_METADATA,
      code: 'code-1',
      redirectUri: REDIRECT_URI,
      clientId: CLIENT_ID,
      codeVerifier: 'verifier-1',
      sessionKey: key,
      requestedPermissions: PERMISSIONS,
      fetchFn,
    });
    expect(result.accessToken).toBe('at-1');
    expect(result.refreshToken).toBe('rt-1');
    expect(result.delegation.verificationMethod).toBe(key.keyId);

    const call = calls[0]!;
    expect(call.url).toBe(SERVER_METADATA.tokenEndpoint);
    expect(call.init.method).toBe('POST');
    const form = new URLSearchParams(call.init.body as string);
    expect(form.get('grant_type')).toBe('authorization_code');
    expect(form.get('code_verifier')).toBe('verifier-1');

    const proof = (call.init.headers as Record<string, string>)[
      SESSION_PROOF_HEADER
    ]!;
    const claims = decodeJwt(proof);
    expect(claims.htu).toBe(SERVER_METADATA.tokenEndpoint);
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode('code-1'),
    );
    expect(claims.cred_hash).toBe(Buffer.from(digest).toString('base64url'));
  });

  it('exchangeDelegationCode maps invalid_grant to INVALID_GRANT', async () => {
    const { fetchFn } = mockFetch(() =>
      jsonResponse({ error: 'invalid_grant' }, 400),
    );
    await expect(
      exchangeDelegationCode({
        metadata: SERVER_METADATA,
        code: 'code-1',
        redirectUri: REDIRECT_URI,
        clientId: CLIENT_ID,
        codeVerifier: 'v',
        sessionKey: key,
        requestedPermissions: PERMISSIONS,
        fetchFn,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_GRANT', status: 400 });
  });

  it('renewDelegation posts JSON and maps renewal_conflict', async () => {
    const { fetchFn, calls } = mockFetch(() =>
      jsonResponse({ error: 'renewal_conflict' }, 409),
    );
    await expect(
      renewDelegation({
        metadata: SERVER_METADATA,
        clientId: CLIENT_ID,
        refreshToken: 'rt-1',
        sessionKey: key,
        requestedPermissions: PERMISSIONS,
        fetchFn,
      }),
    ).rejects.toMatchObject({ code: 'RENEWAL_CONFLICT', status: 409 });

    const call = calls[0]!;
    expect(call.url).toBe(SERVER_METADATA.tinycloudDelegationRenewEndpoint);
    expect(
      (call.init.headers as Record<string, string>)['Content-Type'],
    ).toBe('application/json');
    const body = JSON.parse(call.init.body as string);
    expect(body).toEqual({ client_id: CLIENT_ID, refresh_token: 'rt-1' });

    const proof = (call.init.headers as Record<string, string>)[
      SESSION_PROOF_HEADER
    ]!;
    const claims = decodeJwt(proof);
    expect(claims.htu).toBe(SERVER_METADATA.tinycloudDelegationRenewEndpoint);
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode('rt-1'),
    );
    expect(claims.cred_hash).toBe(Buffer.from(digest).toString('base64url'));
  });

  it('renewDelegation returns the rotated token and validates the delegation', async () => {
    const { fetchFn } = mockFetch(() =>
      jsonResponse({
        refresh_token: 'rt-2',
        expires_in: 3600,
        tinycloud_delegation: delegationFor(key.keyId),
      }),
    );
    const result = await renewDelegation({
      metadata: SERVER_METADATA,
      clientId: CLIENT_ID,
      refreshToken: 'rt-1',
      sessionKey: key,
      requestedPermissions: PERMISSIONS,
      fetchFn,
    });
    expect(result.refreshToken).toBe('rt-2');
    expect(result.delegation.verificationMethod).toBe(key.keyId);
  });

  it('revokeDelegation resolves on 200 and on invalid_grant, throws otherwise', async () => {
    const ok = mockFetch(() => jsonResponse({}, 200));
    await revokeDelegation({
      metadata: SERVER_METADATA,
      clientId: CLIENT_ID,
      refreshToken: 'rt-1',
      sessionKey: key,
      fetchFn: ok.fetchFn,
    });
    expect(ok.calls[0]!.url).toBe(
      SERVER_METADATA.tinycloudDelegationRevocationEndpoint,
    );

    const gone = mockFetch(() => jsonResponse({ error: 'invalid_grant' }, 400));
    await expect(
      revokeDelegation({
        metadata: SERVER_METADATA,
        clientId: CLIENT_ID,
        refreshToken: 'rt-1',
        sessionKey: key,
        fetchFn: gone.fetchFn,
      }),
    ).resolves.toBeUndefined();

    const denied = mockFetch(() =>
      jsonResponse({ error: 'invalid_session_proof' }, 401),
    );
    await expect(
      revokeDelegation({
        metadata: SERVER_METADATA,
        clientId: CLIENT_ID,
        refreshToken: 'rt-1',
        sessionKey: key,
        fetchFn: denied.fetchFn,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_GRANT', status: 401 });
  });
});

// ======= isPermissionSubset =======

describe('isPermissionSubset', () => {
  it('covers prefix grants and exact paths', () => {
    expect(
      isPermissionSubset(
        [
          {
            service: 'kv',
            space: 'applications',
            path: 'app/x/y',
            actions: ['get'],
          },
        ],
        [
          {
            service: 'kv',
            space: 'applications',
            path: 'app/x/',
            actions: ['get', 'put'],
          },
        ],
      ),
    ).toBe(true);
    // non-trailing-slash requested path is exact match only
    expect(
      isPermissionSubset(
        [
          {
            service: 'sql',
            space: 'applications',
            path: 'app/db/child',
            actions: ['read'],
          },
        ],
        [
          {
            service: 'sql',
            space: 'applications',
            path: 'app/db',
            actions: ['read'],
          },
        ],
      ),
    ).toBe(false);
  });
});
