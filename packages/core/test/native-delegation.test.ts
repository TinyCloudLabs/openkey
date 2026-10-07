/**
 * Unit tests for the native TinyCloud delegation module (TC-774 S1).
 *
 * Server endpoints do not exist yet, so every client is exercised through
 * an injected mock fetch. The proof JWS is verified with `jose` as a real
 * EdDSA round-trip.
 */

import { describe, expect, it } from 'bun:test';
import { importJWK, compactVerify, decodeProtectedHeader, decodeJwt, calculateJwkThumbprint } from 'jose';
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
  sessionJktForPublicJwk,
  CAPABILITIES_READ_PERMISSION,
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
  delegationNeedsRenewalNow,
  parseRetryAfterSeconds,
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

function jsonResponse(
  body: unknown,
  status = 200,
  headers?: Record<string, string>,
): NativeFetchResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: headers
      ? { get: (name: string) => headers[name] ?? null }
      : undefined,
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

// Spec "Permissions": fully-qualified service and action names, plus the
// mandatory tinycloud.capabilities/read entry.
const PERMISSIONS: NativeDelegationPermission[] = [
  CAPABILITIES_READ_PERMISSION,
  {
    service: 'tinycloud.kv',
    space: 'applications',
    path: 'xyz.tinycloud.tinychat/threads/',
    actions: [
      'tinycloud.kv/get',
      'tinycloud.kv/put',
      'tinycloud.kv/list',
      'tinycloud.kv/del',
      'tinycloud.kv/metadata',
    ],
  },
  {
    service: 'tinycloud.sql',
    space: 'applications',
    path: 'xyz.tinycloud.tinychat/threads',
    actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'],
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
    address: '0xabc',
    chainId: 1,
    ownerDid: 'did:pkh:eip155:1:0xabc',
    spaceId: 'tinycloud:pkh:eip155:1:0xabc:applications',
    verificationMethod: keyId,
    siwe: 'siwe-bytes',
    signature: '0xsig',
    delegationHeader: { Authorization: 'delegation-ucan' },
    delegationCid: 'bafy...',
    issuedAt: new Date().toISOString(),
    expiresAt: FUTURE,
    renewableUntil: new Date(Date.now() + 30 * 86400_000).toISOString(),
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
      // Discovery issuer mismatch: a metadata-validation failure, not a
      // callback mismatch — reported as SERVER with detail preserved.
      expect((error as OpenKeyNativeError).code).toBe('SERVER');
      expect((error as OpenKeyNativeError).message).toContain('issuer');
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
    expect(key.publicJwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: key.publicJwk.x,
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
  it('prepends tinycloud.capabilities/read when the caller omits it', () => {
    const key = generateSessionKeypair();
    const details = buildAuthorizationDetails({
      sessionKey: key,
      permissions: [PERMISSIONS[1]!],
    });
    expect(details[0]!.permissions).toEqual([
      CAPABILITIES_READ_PERMISSION,
      PERMISSIONS[1],
    ]);
    // a caller that already includes it is unchanged
    const withEntry = buildAuthorizationDetails({
      sessionKey: key,
      permissions: PERMISSIONS,
    });
    expect(withEntry[0]!.permissions).toEqual(PERMISSIONS);
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

  it('rejects an iss mismatch as STATE_MISMATCH', () => {
    expectCode(
      () =>
        parseNativeCallback({
          url: `${base}?code=code-1&state=state-1&iss=${encodeURIComponent('https://evil.example.com/api/auth')}`,
          ...opts,
        }),
      'STATE_MISMATCH',
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
      'STATE_MISMATCH',
    );
  });

  it('never copies the callback URL or its params into error messages', () => {
    // Unparseable callback
    try {
      parseNativeCallback({
        url: 'not a url?code=SECRET_CODE&state=SECRET_STATE',
        expectedState: 'SECRET_STATE',
        issuer: ISSUER,
      });
      expect.unreachable();
    } catch (error) {
      const message = (error as OpenKeyNativeError).message;
      expect(message).not.toContain('SECRET_CODE');
      expect(message).not.toContain('not a url');
    }
    // iss mismatch: the URL value must not appear in the message
    try {
      parseNativeCallback({
        url: `myapp://cb?code=SECRET_CODE&state=state-1&iss=${encodeURIComponent('https://evil.example.com/LEAK_MARKER')}`,
        expectedState: 'state-1',
        issuer: ISSUER,
      });
      expect.unreachable();
    } catch (error) {
      const message = (error as OpenKeyNativeError).message;
      expect(message).not.toContain('LEAK_MARKER');
      expect(message).not.toContain('SECRET_CODE');
    }
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
    });

    const parts = jws.split('.');
    expect(parts).toHaveLength(3);

    const header = decodeProtectedHeader(jws);
    expect(header.typ).toBe(SESSION_PROOF_TYP);
    expect(header.alg).toBe('EdDSA');
    // kid = RFC 7638 JWK thumbprint (the stored sessionJkt), checked with
    // jose's independent implementation.
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: key.publicJwk.x };
    expect(header.kid).toBe(await calculateJwkThumbprint(jwk, 'sha256'));
    expect(header.kid).toBe(await sessionJktForPublicJwk(key.publicJwk));

    const publicKey = await importJWK(jwk, 'EdDSA');
    const { payload } = await compactVerify(jws, publicKey);
    const claims = JSON.parse(new TextDecoder().decode(payload));

    // Spec: payload is exactly these six claims.
    expect(Object.keys(claims).sort()).toEqual(
      ['client_id', 'cred_hash', 'htm', 'htu', 'iat', 'jti'].sort(),
    );
    expect(claims.htm).toBe('POST');
    expect(claims.htu).toBe(METADATA.token_endpoint);
    expect(claims.client_id).toBe(CLIENT_ID);
    expect(claims.jti).toMatch(/^.{16,128}$/);
    expect(typeof claims.iat).toBe('number');

    // cred_hash = b64url(sha256(credential))
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(credential),
    );
    expect(claims.cred_hash).toBe(
      Buffer.from(digest).toString('base64url'),
    );

    // A proof over a different credential has a different cred_hash.
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

  it('kid is the RFC 8037 §A.3 JWK thumbprint vector', async () => {
    // RFC 8037 §A.3 Ed25519 public key; thumbprint computed independently.
    const jwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
    };
    expect(await sessionJktForPublicJwk(jwk)).toBe(
      'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
    );
    expect(await calculateJwkThumbprint(jwk, 'sha256')).toBe(
      'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
    );
  });

describe('delegationNeedsRenewalNow', () => {
  const now = Date.now();
  const issued = new Date(now - 5 * 60_000).toISOString();

  it('is true when less than the lead time remains', () => {
    // 60 s left of a 1 h delegation (lead = min(10 min, 15 min) = 10 min)
    expect(
      delegationNeedsRenewalNow({
        expiresAt: new Date(now + 60_000).toISOString(),
        issuedAt: issued,
      }),
    ).toBe(true);
  });

  it('is false when more than the lead time remains', () => {
    // 50 min left of a 55-min-old 1 h delegation → lifetime ≈ 65 min,
    // lead = min(10 min, ~16 min) = 10 min
    expect(
      delegationNeedsRenewalNow({
        expiresAt: new Date(now + 50 * 60_000).toISOString(),
        issuedAt: issued,
      }),
    ).toBe(false);
  });

  it('uses the full 10-minute lead when issuedAt is missing', () => {
    expect(
      delegationNeedsRenewalNow({
        expiresAt: new Date(now + 9 * 60_000).toISOString(),
      }),
    ).toBe(true);
    expect(
      delegationNeedsRenewalNow({
        expiresAt: new Date(now + 11 * 60_000).toISOString(),
      }),
    ).toBe(false);
  });
});

// ======= Delegation validation =======

describe('validateTinyCloudDelegation', () => {
  const key = generateSessionKeypair();
  const opts = {
    sessionKey: key,
    requestedPermissions: PERMISSIONS,
    expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
  };

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
              { ...PERMISSIONS[1]!, actions: [...PERMISSIONS[1]!.actions, 'tinycloud.kv/admin'] },
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
              { service: 'tinycloud.kv', space: 'applications', actions: ['tinycloud.kv/get'] },
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
                service: 'tinycloud.encryption',
                space: 'applications',
                path: 'x',
                actions: ['tinycloud.encryption/unwrap'],
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
              service: 'tinycloud.kv',
              space: 'applications',
              path: 'xyz.tinycloud.tinychat/threads/abc',
              actions: ['tinycloud.kv/get'],
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

  it('rejects an unexpected tinycloudHost when expectedTinycloudHost is set', () => {
    expectCode(
      () =>
        validateTinyCloudDelegation(delegationFor(key.keyId), {
          ...opts,
          expectedTinycloudHost: 'https://other.node.example.com',
        }),
      'SERVER',
    );
    expect(() =>
      validateTinyCloudDelegation(delegationFor(key.keyId), {
        ...opts,
        expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
      }),
    ).not.toThrow();
  });

  it('rejects a malformed expiresAt (non-finite, non-positive, bad string)', () => {
    for (const expiresAt of [NaN, Infinity, -Infinity, 0, -5, 'tomorrow']) {
      expectCode(
        () =>
          validateTinyCloudDelegation(
            delegationFor(key.keyId, { expiresAt }),
            opts,
          ),
        'SERVER',
      );
    }
  });

  it('fails closed when expectedTinycloudHost is absent or empty', () => {
    expectCode(
      () =>
        validateTinyCloudDelegation(delegationFor(key.keyId), {
          ...opts,
          expectedTinycloudHost: '',
        }),
      'SERVER',
    );
    expectCode(
      () =>
        validateTinyCloudDelegation(delegationFor(key.keyId), {
          // Bypass the required field - a JS caller could still omit it.
          ...opts,
          expectedTinycloudHost: undefined as unknown as string,
        }),
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
        expires_in: 300,
        expires_at: 1791374700,
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
      expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
      fetchFn,
    });
    expect(result.accessToken).toBe('at-1');
    expect(result.refreshToken).toBe('rt-1');
    expect(result.expiresIn).toBe(300);
    expect(result.accessTokenExpiresAt).toBe(1791374700);
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
        expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
        fetchFn,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_GRANT', status: 400 });
  });

  it('503 on code exchange surfaces TEMPORARILY_UNAVAILABLE without resending the code', async () => {
    const { fetchFn, calls } = mockFetch(() =>
      jsonResponse(
        { error: 'temporarily_unavailable' },
        503,
        { 'Retry-After': '2' },
      ),
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
        expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
        fetchFn,
      }),
    ).rejects.toMatchObject({
      code: 'TEMPORARILY_UNAVAILABLE',
      status: 503,
      retryAfterSeconds: 2,
    });
    // Exactly one request: the code is spent either way.
    expect(calls).toHaveLength(1);
  });

  it('hosting: "failed" in a success response maps to SPACE_UNAVAILABLE', async () => {
    const { fetchFn } = mockFetch(() =>
      jsonResponse({
        access_token: 'at-1',
        refresh_token: 'rt-1',
        expires_in: 300,
        token_type: 'Bearer',
        tinycloud_delegation: delegationFor(key.keyId, { hosting: 'failed' }),
      }),
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
        expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
        fetchFn,
      }),
    ).rejects.toMatchObject({ code: 'SPACE_UNAVAILABLE' });
  });

  it('maps provider code-exchange errors to INVALID_GRANT (terminal, one request)', async () => {
    for (const error of ['invalid_verification', 'invalid_request', 'invalid_client']) {
      const { fetchFn, calls } = mockFetch(() =>
        jsonResponse({ error, error_description: 'detail' }, 400),
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
          expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
          fetchFn,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_GRANT', serverError: error });
      expect(calls).toHaveLength(1);
    }
  });

  it('renewDelegation posts form-encoded fields and maps renewal_conflict', async () => {
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
        expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
        siweNonce: 'renewnonce1',
        permissionsSubset: [PERMISSIONS[1]!],
        fetchFn,
      }),
    ).rejects.toMatchObject({ code: 'RENEWAL_CONFLICT', status: 409 });

    const call = calls[0]!;
    expect(call.url).toBe(SERVER_METADATA.tinycloudDelegationRenewEndpoint);
    expect(
      (call.init.headers as Record<string, string>)['Content-Type'],
    ).toBe('application/x-www-form-urlencoded');
    const body = new URLSearchParams(call.init.body as string);
    expect(body.get('client_id')).toBe(CLIENT_ID);
    expect(body.get('refresh_token')).toBe('rt-1');
    expect(body.get('siwe_nonce')).toBe('renewnonce1');
    // authorization_details: PAR shape, subset only, no ttl_seconds
    const details = JSON.parse(body.get('authorization_details')!);
    expect(details[0].type).toBe('tinycloud_delegation');
    expect(details[0].session_key.x).toBe(key.publicJwk.x);
    expect(details[0].permissions).toEqual([
      CAPABILITIES_READ_PERMISSION,
      PERMISSIONS[1],
    ]);
    expect(details[0]).not.toHaveProperty('ttl_seconds');

    const proof = (call.init.headers as Record<string, string>)[
      SESSION_PROOF_HEADER
    ]!;
    const claims = decodeJwt(proof);
    expect(claims.htu).toBe(SERVER_METADATA.tinycloudDelegationRenewEndpoint);
    // proof payload carries exactly the six spec claims — the nonce and
    // authorization_details travel in the body, not the JWS.
    expect(Object.keys(claims).sort()).toEqual(
      ['client_id', 'cred_hash', 'htm', 'htu', 'iat', 'jti'].sort(),
    );
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode('rt-1'),
    );
    expect(claims.cred_hash).toBe(Buffer.from(digest).toString('base64url'));
  });

  it('429 renewal_too_soon waits Retry-After and retries once with the same token', async () => {
    const slept: number[] = [];
    let attempts = 0;
    const { fetchFn, calls } = mockFetch(() => {
      attempts += 1;
      return attempts === 1
        ? jsonResponse(
            { error: 'renewal_too_soon' },
            429,
            { 'Retry-After': '7' },
          )
        : jsonResponse({
            refresh_token: 'rt-2',
            expires_in: 604800,
            tinycloud_delegation: delegationFor(key.keyId),
          });
    });
    const result = await renewDelegation({
      metadata: SERVER_METADATA,
      clientId: CLIENT_ID,
      refreshToken: 'rt-1',
      sessionKey: key,
      requestedPermissions: PERMISSIONS,
      expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
      fetchFn,
      sleepFn: (ms) => {
        slept.push(ms);
        return Promise.resolve();
      },
    });
    expect(result.refreshToken).toBe('rt-2');
    expect(slept).toEqual([7000]);
    // Same token on both attempts
    expect(calls).toHaveLength(2);
    for (const call of calls) {
      expect(new URLSearchParams(call.init.body as string).get('refresh_token')).toBe('rt-1');
    }
  });

  it('a second consecutive 429 propagates RENEWAL_TOO_SOON with retryAfterSeconds', async () => {
    const slept: number[] = [];
    const { fetchFn } = mockFetch(() =>
      jsonResponse({ error: 'renewal_too_soon' }, 429, { 'Retry-After': '3' }),
    );
    await expect(
      renewDelegation({
        metadata: SERVER_METADATA,
        clientId: CLIENT_ID,
        refreshToken: 'rt-1',
        sessionKey: key,
        requestedPermissions: PERMISSIONS,
        expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
        fetchFn,
        sleepFn: (ms) => {
          slept.push(ms);
          return Promise.resolve();
        },
      }),
    ).rejects.toMatchObject({
      code: 'RENEWAL_TOO_SOON',
      status: 429,
      serverError: 'renewal_too_soon',
      retryAfterSeconds: 3,
    });
    expect(slept).toEqual([3000]);
  });

  it('503 on renew waits Retry-After and retries with a fresh proof', async () => {
    const slept: number[] = [];
    let attempts = 0;
    const { fetchFn, calls } = mockFetch(() => {
      attempts += 1;
      return attempts === 1
        ? jsonResponse(
            { error: 'temporarily_unavailable' },
            503,
            { 'Retry-After': '2' },
          )
        : jsonResponse({
            refresh_token: 'rt-2',
            tinycloud_delegation: delegationFor(key.keyId),
          });
    });
    const result = await renewDelegation({
      metadata: SERVER_METADATA,
      clientId: CLIENT_ID,
      refreshToken: 'rt-1',
      sessionKey: key,
      requestedPermissions: PERMISSIONS,
      expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
      fetchFn,
      sleepFn: (ms) => {
        slept.push(ms);
        return Promise.resolve();
      },
    });
    expect(result.refreshToken).toBe('rt-2');
    expect(slept).toEqual([2000]);
    expect(calls).toHaveLength(2);
    // Fresh proofs: distinct jti on the retry.
    const jtis = calls.map(
      (call) =>
        decodeJwt(
          (call.init.headers as Record<string, string>)[SESSION_PROOF_HEADER]!,
        ).jti,
    );
    expect(jtis[0]).not.toBe(jtis[1]);
  });

  it('renewal_conflict and invalid_session_proof are terminal (no retry)', async () => {
    for (const [status, serverError, code] of [
      [409, 'renewal_conflict', 'RENEWAL_CONFLICT'],
      [401, 'invalid_session_proof', 'INVALID_GRANT'],
    ] as const) {
      const { fetchFn, calls } = mockFetch(() =>
        jsonResponse({ error: serverError }, status),
      );
      await expect(
        renewDelegation({
          metadata: SERVER_METADATA,
          clientId: CLIENT_ID,
          refreshToken: 'rt-1',
          sessionKey: key,
          requestedPermissions: PERMISSIONS,
          expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
          fetchFn,
          sleepFn: () => Promise.reject(new Error('must not sleep')),
        }),
      ).rejects.toMatchObject({ code });
      expect(calls).toHaveLength(1);
    }
  });

  it('renewDelegation maps access_denied to ACCESS_DENIED', async () => {
    const { fetchFn } = mockFetch(() =>
      jsonResponse({ error: 'access_denied' }, 400),
    );
    await expect(
      renewDelegation({
        metadata: SERVER_METADATA,
        clientId: CLIENT_ID,
        refreshToken: 'rt-1',
        sessionKey: key,
        requestedPermissions: PERMISSIONS,
        expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
        fetchFn,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('renewDelegation returns the rotated token and validates the delegation', async () => {
    const { fetchFn } = mockFetch(() =>
      jsonResponse({
        refresh_token: 'rt-2',
        expires_in: 604800,
        tinycloud_delegation: delegationFor(key.keyId),
      }),
    );
    const result = await renewDelegation({
      metadata: SERVER_METADATA,
      clientId: CLIENT_ID,
      refreshToken: 'rt-1',
      sessionKey: key,
      requestedPermissions: PERMISSIONS,
      expectedTinycloudHost: 'https://tee.node.tinycloud.xyz',
      fetchFn,
    });
    expect(result.refreshToken).toBe('rt-2');
    expect(result.delegation.verificationMethod).toBe(key.keyId);
  });

  it('revokeDelegation posts form-encoded fields; 200 resolves, 401 propagates', async () => {
    const ok = mockFetch(() => jsonResponse({}, 200));
    await revokeDelegation({
      metadata: SERVER_METADATA,
      clientId: CLIENT_ID,
      refreshToken: 'rt-1',
      sessionKey: key,
      fetchFn: ok.fetchFn,
    });
    const call = ok.calls[0]!;
    expect(call.url).toBe(
      SERVER_METADATA.tinycloudDelegationRevocationEndpoint,
    );
    expect(
      (call.init.headers as Record<string, string>)['Content-Type'],
    ).toBe('application/x-www-form-urlencoded');
    const body = new URLSearchParams(call.init.body as string);
    expect(body.get('client_id')).toBe(CLIENT_ID);
    expect(body.get('refresh_token')).toBe('rt-1');

    const proof = (call.init.headers as Record<string, string>)[
      SESSION_PROOF_HEADER
    ]!;
    const claims = decodeJwt(proof);
    expect(claims.htu).toBe(
      SERVER_METADATA.tinycloudDelegationRevocationEndpoint,
    );

    // Spec: unknown token or bad proof → 401 invalid_session_proof, which
    // maps to INVALID_GRANT and propagates (no idempotent swallow).
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

  it('503 on revoke waits Retry-After and retries once with the same token', async () => {
    const slept: number[] = [];
    let attempts = 0;
    const { fetchFn, calls } = mockFetch(() => {
      attempts += 1;
      return attempts === 1
        ? jsonResponse(
            { error: 'temporarily_unavailable' },
            503,
            { 'Retry-After': '2' },
          )
        : jsonResponse({}, 200);
    });
    await revokeDelegation({
      metadata: SERVER_METADATA,
      clientId: CLIENT_ID,
      refreshToken: 'rt-1',
      sessionKey: key,
      fetchFn,
      sleepFn: (ms) => {
        slept.push(ms);
        return Promise.resolve();
      },
    });
    expect(slept).toEqual([2000]);
    expect(calls).toHaveLength(2);
    for (const call of calls) {
      expect(
        new URLSearchParams(call.init.body as string).get('refresh_token'),
      ).toBe('rt-1');
    }
  });

  it('a second 503 on revoke propagates TEMPORARILY_UNAVAILABLE', async () => {
    const { fetchFn } = mockFetch(() =>
      jsonResponse(
        { error: 'temporarily_unavailable' },
        503,
        { 'Retry-After': '2' },
      ),
    );
    await expect(
      revokeDelegation({
        metadata: SERVER_METADATA,
        clientId: CLIENT_ID,
        refreshToken: 'rt-1',
        sessionKey: key,
        fetchFn,
        sleepFn: () => Promise.resolve(),
      }),
    ).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE', status: 503 });
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
