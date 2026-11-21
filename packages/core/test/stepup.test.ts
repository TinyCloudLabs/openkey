/**
 * Unit tests for native step-up (TC-3569): the request, code exchange,
 * validation, renewal additions and per-app revoke, plus the Keccak and
 * EIP-191 recovery they rely on. Every endpoint is an injected mock fetch.
 */

import { describe, expect, it } from 'bun:test';
import { decodeJwt } from 'jose';
import { secp256k1 } from '@noble/curves/secp256k1';

import {
  OpenKeyNativeError,
  SESSION_PROOF_HEADER,
  discoverOpenKeyServer,
  exchangeStepUpCode,
  generateSessionKeypair,
  isNativeStepUpAppId,
  renewDelegation,
  requestStepUp,
  revokeDelegation,
  revokeStepUp,
  validateTinyCloudStepUp,
  type NativeFetch,
  type NativeFetchInit,
  type NativeFetchResponse,
  type NativeSessionKeypair,
  type NativeStepUpPermission,
  type OpenKeyServerMetadata,
  type TinyCloudStepUp,
  type ValidateStepUpOptions,
} from '../src/index';
import { keccak256, recoverPersonalSignAddress } from '../src/eth-signature';

const ISSUER = 'https://api.openkey.so/api/auth';
const ORIGIN = 'https://api.openkey.so';
const HOST = 'https://tee.node.tinycloud.xyz';
const CLIENT_ID = 'native-app';
const REDIRECT_URI = 'xyz.tinycloud.exo://openkey/stepup';
const APP = 'xyz.tinycloud.explorer';
const STEP_UP_ENDPOINT = `${ORIGIN}/api/auth/oauth2/tinycloud/stepup`;

const METADATA: OpenKeyServerMetadata = {
  issuer: ISSUER,
  origin: ORIGIN,
  authorizationEndpoint: `${ORIGIN}/api/auth/oauth2/authorize`,
  tokenEndpoint: `${ORIGIN}/api/auth/oauth2/token`,
  pushedAuthorizationRequestEndpoint: `${ORIGIN}/api/auth/oauth2/par`,
  tinycloudDelegationRenewEndpoint: `${ORIGIN}/api/auth/oauth2/tinycloud/renew`,
  tinycloudDelegationRevocationEndpoint: `${ORIGIN}/api/auth/oauth2/tinycloud/revoke`,
  tinycloudDelegationStepUpEndpoint: STEP_UP_ENDPOINT,
};

const PERMISSIONS: NativeStepUpPermission[] = [
  { service: 'tinycloud.kv', space: 'public', path: '', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
  { service: 'tinycloud.sql', space: 'applications', path: 'default', actions: ['tinycloud.sql/read'] },
];

const hex = (bytes: Uint8Array) => [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
const utf8 = (text: string) => new TextEncoder().encode(text);

function ownerFrom(seed: number) {
  const privateKey = new Uint8Array(32);
  privateKey[31] = seed;
  const address = `0x${hex(keccak256(secp256k1.getPublicKey(privateKey, false).slice(1)).slice(12))}`;
  return { privateKey, address };
}

/** EIP-191 `personal_sign`. */
function personalSign(privateKey: Uint8Array, message: string): string {
  const body = utf8(message);
  const prefix = utf8(`\x19Ethereum Signed Message:\n${body.length}`);
  const signature = secp256k1.sign(keccak256(new Uint8Array([...prefix, ...body])), privateKey);
  return `0x${signature.toCompactHex()}${(27 + signature.recovery).toString(16)}`;
}

const owner = ownerFrom(1);
const stranger = ownerFrom(2);

interface StepUpBuild {
  key: NativeSessionKeypair;
  signer?: typeof owner;
  address?: string;
  siwe?: (defaults: { address: string; did: string; expiresAt: string; lines: string[] }) => string;
  override?: Record<string, unknown>;
}

function buildStepUp(build: StepUpBuild): Record<string, unknown> {
  const address = build.address ?? owner.address;
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
  const did = build.key.keyId.split('#')[0]!;
  const lines = [
    'openkey.so wants you to sign in with your Ethereum account:', address, '', 'Delegate read access', '',
    `URI: ${did}`, 'Version: 1', 'Chain ID: 1', 'Nonce: stepupnonce1', `Issued At: ${issuedAt}`, `Expiration Time: ${expiresAt}`,
  ];
  const siwe = build.siwe ? build.siwe({ address, did, expiresAt, lines }) : lines.join('\n');
  return {
    version: 1, appId: APP, grantId: 'grant-1', address, chainId: 1, ownerDid: `did:pkh:eip155:1:${address}`,
    spaces: [{ space: 'public', spaceId: `tinycloud:pkh:eip155:1:${address}:public` },
      { space: 'applications', spaceId: `tinycloud:pkh:eip155:1:${address}:applications` }],
    verificationMethod: build.key.keyId, siwe, signature: personalSign((build.signer ?? owner).privateKey, siwe),
    delegationHeader: { Authorization: 'Bearer fake' }, delegationCid: 'bafystepup', issuedAt, expiresAt,
    renewableUntil: new Date(Date.now() + 86_400_000).toISOString(), permissions: PERMISSIONS, tinycloudHost: HOST, hosting: 'existing',
    ...build.override,
  };
}

function validateOptions(key: NativeSessionKeypair): ValidateStepUpOptions {
  return { sessionKey: key, appId: APP, requestedPermissions: PERMISSIONS, expectedTinycloudHost: HOST,
    expectedGrantId: 'grant-1', expectedAddress: owner.address, expectedChainId: 1,
    grantRenewableUntil: new Date(Date.now() + 2 * 86_400_000).toISOString() };
}

function jsonResponse(status: number, data: unknown, retryAfter?: string): NativeFetchResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => data, headers: { get: () => retryAfter ?? null } };
}

interface Call { url: string; init?: NativeFetchInit }
function recorder(reply: (call: Call) => NativeFetchResponse | Promise<NativeFetchResponse>): { fetchFn: NativeFetch; calls: Call[] } {
  const calls: Call[] = [];
  return { calls, fetchFn: async (url, init) => { const call = { url, init }; calls.push(call); return reply(call); } };
}

function thrownCode(attempt: () => unknown): string | undefined {
  try {
    attempt();
  } catch (error) {
    return error instanceof OpenKeyNativeError ? error.code : 'NOT_AN_OPENKEY_ERROR';
  }
  return undefined;
}

describe('keccak256 and personal_sign recovery', () => {
  it('matches the published Keccak-256 vectors', () => {
    expect(hex(keccak256(new Uint8Array()))).toBe('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
    expect(hex(keccak256(utf8('abc')))).toBe('4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
    // Around the 136-byte rate boundary the digest stays 32 bytes; the multi-block recovery test below pins correctness.
    for (const length of [135, 136, 137]) expect(keccak256(new Uint8Array(length).fill(97))).toHaveLength(32);
  });

  it('recovers the signer of a long multi-block message and nothing for garbage', () => {
    const message = 'line of text\n'.repeat(60);
    expect(recoverPersonalSignAddress(message, personalSign(owner.privateKey, message))).toBe(owner.address);
    expect(recoverPersonalSignAddress(`${message}x`, personalSign(owner.privateKey, message))).not.toBe(owner.address);
    expect(recoverPersonalSignAddress(message, '0x1234')).toBeNull();
    expect(recoverPersonalSignAddress(message, `0x${'00'.repeat(65)}`)).toBeNull();
  });
});

describe('validateTinyCloudStepUp', () => {
  const key = generateSessionKeypair();

  it('accepts a signed step-up and returns a clean copy', () => {
    const stepUp = validateTinyCloudStepUp({ ...buildStepUp({ key }), extra: 'dropped' }, validateOptions(key));
    expect(stepUp).toMatchObject({ appId: APP, grantId: 'grant-1', hosting: 'existing', delegationCid: 'bafystepup' });
    expect('extra' in stepUp).toBe(false);
    expect(stepUp.permissions).toEqual(PERMISSIONS);
  });

  it('accepts the ceiling-wide empty KV path against an empty requested path', () => {
    const wide: NativeStepUpPermission[] = [PERMISSIONS[0]!];
    const built = buildStepUp({ key, override: { permissions: wide, spaces: [{ space: 'public', spaceId: `tinycloud:pkh:eip155:1:${owner.address}:public` }] } });
    expect(validateTinyCloudStepUp(built, { ...validateOptions(key), requestedPermissions: wide }).permissions).toEqual(wide);
  });

  const other = generateSessionKeypair();
  const tampered: Array<[string, (key: NativeSessionKeypair) => Record<string, unknown>]> = [
    ['signed by another account', (k) => buildStepUp({ key: k, signer: stranger })],
    ['for another owner address', (k) => buildStepUp({ key: k, address: stranger.address })],
    ['a signed message naming another account', (k) => buildStepUp({ key: k, siwe: ({ did, expiresAt }) =>
      ['openkey.so wants you to sign in with your Ethereum account:', stranger.address, '', `URI: ${did}`, `Expiration Time: ${expiresAt}`].join('\n') })],
    ['a signed message for another delegate', (k) => buildStepUp({ key: k, siwe: ({ address, expiresAt }) =>
      ['openkey.so wants you to sign in with your Ethereum account:', address, '', `URI: ${other.did}`, `Expiration Time: ${expiresAt}`].join('\n') })],
    ['a signed message with another expiry', (k) => buildStepUp({ key: k, siwe: ({ address, did }) =>
      ['openkey.so wants you to sign in with your Ethereum account:', address, '', `URI: ${did}`, 'Expiration Time: 2099-01-01T00:00:00.000Z'].join('\n') })],
    ['a signed message with a duplicated URI line', (k) => buildStepUp({ key: k, siwe: ({ lines }) => [...lines, `URI: ${other.did}`].join('\n') })],
    ['a signed message repeating its own URI line', (k) => buildStepUp({ key: k, siwe: ({ lines }) => [...lines, lines[5]!].join('\n') })],
    ['a signed message without a URI line', (k) => buildStepUp({ key: k, siwe: ({ lines }) => lines.filter((line) => !line.startsWith('URI: ')).join('\n') })],
    ['a signed message for another chain', (k) => buildStepUp({ key: k, siwe: ({ lines }) => lines.map((line) => (line === 'Chain ID: 1' ? 'Chain ID: 137' : line)).join('\n') })],
    ['a signed message without a Chain ID line', (k) => buildStepUp({ key: k, siwe: ({ lines }) => lines.filter((line) => !line.startsWith('Chain ID: ')).join('\n') })],
    ['a signed message with a duplicated Chain ID line', (k) => buildStepUp({ key: k, siwe: ({ lines }) => [...lines, 'Chain ID: 1'].join('\n') })],
    ['a signed message with a duplicated Expiration Time line', (k) => buildStepUp({ key: k, siwe: ({ lines }) => [...lines, lines[10]!].join('\n') })],
    ['delegated to another key', (k) => buildStepUp({ key: k, override: { verificationMethod: other.keyId } })],
    ['for another app', (k) => buildStepUp({ key: k, override: { appId: 'xyz.tinycloud.courier' } })],
    ['for another grant', (k) => buildStepUp({ key: k, override: { grantId: 'grant-2' } })],
    ['with an unknown version', (k) => buildStepUp({ key: k, override: { version: 2 } })],
    ['not hosted on an existing space', (k) => buildStepUp({ key: k, override: { hosting: 'created' } })],
    ['with an owner DID of another address', (k) => buildStepUp({ key: k, override: { ownerDid: `did:pkh:eip155:1:${stranger.address}` } })],
    ['with a space id of another address', (k) => buildStepUp({ key: k, override: {
      spaces: [{ space: 'public', spaceId: `tinycloud:pkh:eip155:1:${stranger.address}:public` },
        { space: 'applications', spaceId: `tinycloud:pkh:eip155:1:${owner.address}:applications` }] } })],
    ['with fewer spaces than permissions', (k) => buildStepUp({ key: k, override: { spaces: [{ space: 'public', spaceId: `tinycloud:pkh:eip155:1:${owner.address}:public` }] } })],
    ['with a write action', (k) => buildStepUp({ key: k, override: { permissions: [{ ...PERMISSIONS[0]!, actions: ['tinycloud.kv/put'] }, PERMISSIONS[1]] } })],
    ['with a permission that was not requested', (k) => buildStepUp({ key: k, override: {
      permissions: [PERMISSIONS[0], PERMISSIONS[1], { service: 'tinycloud.sql', space: 'public', path: 'x', actions: ['tinycloud.sql/read'] }] } })],
    ['on another node', (k) => buildStepUp({ key: k, override: { tinycloudHost: 'https://evil.example' } })],
    ['already expired', (k) => buildStepUp({ key: k, override: { expiresAt: new Date(Date.now() - 1000).toISOString() } })],
    ['outliving its grant', (k) => buildStepUp({ key: k, override: { renewableUntil: new Date(Date.now() - 600_000).toISOString() } })],
    ['without its delegation header', (k) => buildStepUp({ key: k, override: { delegationHeader: {} } })],
    ['without its CID', (k) => buildStepUp({ key: k, override: { delegationCid: '' } })],
  ];
  it.each(tampered)('rejects a step-up %s', (_name, build) => {
    expect(thrownCode(() => validateTinyCloudStepUp(build(key), validateOptions(key)))).toBe('SERVER');
  });

  it('rejects a step-up that outlives the grant the caller holds', () => {
    const built = buildStepUp({ key });
    expect(() => validateTinyCloudStepUp(built, { ...validateOptions(key), grantRenewableUntil: new Date(Date.now() - 3_600_000).toISOString() }))
      .toThrow(OpenKeyNativeError);
  });

  it('binds the signed text to the chain id Home holds', () => {
    expect(thrownCode(() => validateTinyCloudStepUp(buildStepUp({ key }), { ...validateOptions(key), expectedChainId: 137 }))).toBe('SERVER');
  });

  it('fails closed without an expected node and for non-object input', () => {
    expect(() => validateTinyCloudStepUp(buildStepUp({ key }), { ...validateOptions(key), expectedTinycloudHost: '' })).toThrow(OpenKeyNativeError);
    for (const value of [null, undefined, 'x', [], 7]) expect(() => validateTinyCloudStepUp(value, validateOptions(key))).toThrow(OpenKeyNativeError);
  });
});

describe('requestStepUp', () => {
  const key = generateSessionKeypair();
  const base = {
    metadata: METADATA, clientId: CLIENT_ID, refreshToken: 'rt-1', sessionKey: key, appId: APP,
    redirectUri: REDIRECT_URI, state: 'state-state-state-1', codeChallenge: 'c'.repeat(43), permissions: PERMISSIONS,
  };

  it('posts the exact form with a session proof over the refresh token for the step-up endpoint', async () => {
    const { fetchFn, calls } = recorder(() => jsonResponse(201, { request_uri: 'urn:ietf:params:oauth:request_uri:abc', expires_in: 90 }));
    const pushed = await requestStepUp({ ...base, fetchFn });
    expect(pushed).toEqual({ requestUri: 'urn:ietf:params:oauth:request_uri:abc', expiresIn: 90 });
    const call = calls[0]!;
    expect(call.url).toBe(STEP_UP_ENDPOINT);
    expect(call.init?.method).toBe('POST');
    expect(call.init?.headers?.['Content-Type']).toBe('application/x-www-form-urlencoded');
    const form = new URLSearchParams(call.init?.body);
    expect([...form.keys()].sort()).toEqual(['app_id', 'client_id', 'code_challenge', 'code_challenge_method', 'permissions', 'redirect_uri', 'refresh_token', 'state']);
    expect(form.get('app_id')).toBe(APP);
    expect(form.get('refresh_token')).toBe('rt-1');
    expect(form.get('code_challenge_method')).toBe('S256');
    expect(JSON.parse(form.get('permissions')!)).toEqual(PERMISSIONS);
    expect(form.has('session_key')).toBe(false);
    expect(form.has('authorization_details')).toBe(false);
    const claims = decodeJwt(call.init!.headers![SESSION_PROOF_HEADER]!);
    expect(claims).toMatchObject({ htm: 'POST', htu: STEP_UP_ENDPOINT, client_id: CLIENT_ID });
  });

  it('is unavailable without an advertised endpoint and sends nothing', async () => {
    const { fetchFn, calls } = recorder(() => jsonResponse(201, {}));
    const { tinycloudDelegationStepUpEndpoint: _omitted, ...withoutEndpoint } = METADATA;
    await expect(requestStepUp({ ...base, metadata: withoutEndpoint, fetchFn })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls).toHaveLength(0);
  });

  it('refuses a malformed request before any network call', async () => {
    const { fetchFn, calls } = recorder(() => jsonResponse(201, {}));
    await expect(requestStepUp({ ...base, appId: 'not an app', fetchFn })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(requestStepUp({ ...base, permissions: [], fetchFn })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(requestStepUp({ ...base, permissions: [{ ...PERMISSIONS[0]!, actions: ['tinycloud.kv/put'] }], fetchFn }))
      .rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(requestStepUp({ ...base, permissions: [{ ...PERMISSIONS[0]!, space: 'secrets' as never }], fetchFn }))
      .rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(requestStepUp({ ...base, permissions: [{ ...PERMISSIONS[0]!, extra: 1 } as never], fetchFn }))
      .rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    expect(calls).toHaveLength(0);
  });

  const refusals: Array<[number, string, string]> = [
    [404, 'not_found', 'UNAVAILABLE'],
    [400, 'access_denied', 'ACCESS_DENIED'],
    [400, 'consent_required', 'CONSENT_REQUIRED'],
    [400, 'invalid_grant', 'INVALID_GRANT'],
    [400, 'invalid_request', 'INVALID_REQUEST'],
    [400, 'invalid_authorization_details', 'INVALID_REQUEST'],
    [401, 'invalid_session_proof', 'INVALID_GRANT'],
  ];
  it.each(refusals)('maps a %d %s refusal to %s', async (status, error, code) => {
    const { fetchFn } = recorder(() => jsonResponse(status, { error }));
    await expect(requestStepUp({ ...base, fetchFn })).rejects.toMatchObject({ code });
  });

  it('keeps Retry-After on slow_down and retries a 503 once with a fresh proof', async () => {
    const slow = recorder(() => jsonResponse(429, { error: 'slow_down' }, '10'));
    await expect(requestStepUp({ ...base, fetchFn: slow.fetchFn })).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE', retryAfterSeconds: 10 });
    expect(slow.calls).toHaveLength(1);

    let attempt = 0;
    const waits: number[] = [];
    const flaky = recorder(() => (++attempt === 1
      ? jsonResponse(503, { error: 'temporarily_unavailable' }, '3')
      : jsonResponse(201, { request_uri: 'urn:ok' })));
    const pushed = await requestStepUp({ ...base, fetchFn: flaky.fetchFn, sleepFn: async (ms) => { waits.push(ms); } });
    expect(pushed.requestUri).toBe('urn:ok');
    expect(waits).toEqual([3000]);
    const proofs = flaky.calls.map((call) => decodeJwt(call.init!.headers![SESSION_PROOF_HEADER]!).jti);
    expect(new Set(proofs).size).toBe(2);
  });

  it('rejects a 201 without a request_uri', async () => {
    const { fetchFn } = recorder(() => jsonResponse(201, { expires_in: 90 }));
    await expect(requestStepUp({ ...base, fetchFn })).rejects.toMatchObject({ code: 'SERVER' });
  });
});

describe('exchangeStepUpCode', () => {
  const key = generateSessionKeypair();
  const base = {
    metadata: METADATA, code: 'code-1', redirectUri: REDIRECT_URI, clientId: CLIENT_ID, codeVerifier: 'v'.repeat(43), ...validateOptions(key),
  };

  it('redeems the code with the grant key proof and returns the validated step-up', async () => {
    const { fetchFn, calls } = recorder(() => jsonResponse(200, { access_token: 'short', token_type: 'Bearer', tinycloud_stepup: buildStepUp({ key }) }));
    const stepUp: TinyCloudStepUp = await exchangeStepUpCode({ ...base, fetchFn });
    expect(stepUp.appId).toBe(APP);
    const call = calls[0]!;
    expect(call.url).toBe(METADATA.tokenEndpoint);
    const form = new URLSearchParams(call.init?.body);
    expect(Object.fromEntries(form)).toEqual({
      grant_type: 'authorization_code', code: 'code-1', redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, code_verifier: 'v'.repeat(43),
    });
    expect(decodeJwt(call.init!.headers![SESSION_PROOF_HEADER]!)).toMatchObject({ htm: 'POST', htu: METADATA.tokenEndpoint });
  });

  it('refuses a response that carries a refresh token or a grant', async () => {
    for (const extra of [{ refresh_token: 'rogue' }, { tinycloud_delegation: { expiresAt: 1 } }]) {
      const { fetchFn } = recorder(() => jsonResponse(200, { ...extra, tinycloud_stepup: buildStepUp({ key }) }));
      await expect(exchangeStepUpCode({ ...base, fetchFn })).rejects.toMatchObject({ code: 'SERVER' });
    }
  });

  it('rejects a response without tinycloud_stepup and maps token errors', async () => {
    const empty = recorder(() => jsonResponse(200, { access_token: 'short' }));
    await expect(exchangeStepUpCode({ ...base, fetchFn: empty.fetchFn })).rejects.toMatchObject({ code: 'SERVER' });
    const denied = recorder(() => jsonResponse(400, { error: 'invalid_grant' }));
    await expect(exchangeStepUpCode({ ...base, fetchFn: denied.fetchFn })).rejects.toMatchObject({ code: 'INVALID_GRANT' });
    expect(denied.calls).toHaveLength(1);
  });
});

describe('revokeStepUp', () => {
  const key = generateSessionKeypair();
  const base = { metadata: METADATA, clientId: CLIENT_ID, refreshToken: 'rt-1', sessionKey: key };

  it('sends app_id on the revoke endpoint; the grant revoke never does', async () => {
    const one = recorder(() => jsonResponse(200, {}));
    await revokeStepUp({ ...base, appId: APP, fetchFn: one.fetchFn });
    expect(one.calls[0]!.url).toBe(METADATA.tinycloudDelegationRevocationEndpoint);
    expect(Object.fromEntries(new URLSearchParams(one.calls[0]!.init?.body))).toEqual({ client_id: CLIENT_ID, refresh_token: 'rt-1', app_id: APP });
    expect(decodeJwt(one.calls[0]!.init!.headers![SESSION_PROOF_HEADER]!)).toMatchObject({ htu: METADATA.tinycloudDelegationRevocationEndpoint });

    const grant = recorder(() => jsonResponse(200, {}));
    await revokeDelegation({ ...base, fetchFn: grant.fetchFn });
    expect([...new URLSearchParams(grant.calls[0]!.init?.body).keys()].sort()).toEqual(['client_id', 'refresh_token']);
  });

  it('maps a refused app_id and rejects a bad app id before any call', async () => {
    const off = recorder(() => jsonResponse(400, { error: 'invalid_request' }));
    await expect(revokeStepUp({ ...base, appId: APP, fetchFn: off.fetchFn })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(revokeStepUp({ ...base, appId: '../x', fetchFn: off.fetchFn })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    expect(off.calls).toHaveLength(1);
    const dead = recorder(() => jsonResponse(401, { error: 'invalid_session_proof' }));
    await expect(revokeStepUp({ ...base, appId: APP, fetchFn: dead.fetchFn })).rejects.toMatchObject({ code: 'INVALID_GRANT' });
  });
});

describe('renewDelegation step-up additions', () => {
  const key = generateSessionKeypair();
  const held = { [APP]: validateTinyCloudStepUp(buildStepUp({ key }), validateOptions(key)) };
  const home = () => ({
    grantId: 'grant-1', chainId: 1,
    verificationMethod: key.keyId, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), tinycloudHost: HOST, address: owner.address,
    renewableUntil: new Date(Date.now() + 2 * 86_400_000).toISOString(),
    permissions: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }],
  });
  const base = {
    metadata: METADATA, clientId: CLIENT_ID, refreshToken: 'rt-1', sessionKey: key, requestedPermissions: [],
    expectedTinycloudHost: HOST, heldStepUps: held,
  };

  it('returns no step-up member when the response has none', async () => {
    const { fetchFn } = recorder(() => jsonResponse(200, { refresh_token: 'rt-2', tinycloud_delegation: home() }));
    const result = await renewDelegation({ ...base, fetchFn });
    expect(result.refreshToken).toBe('rt-2');
    expect('stepUps' in result).toBe(false);
  });

  it('validates renewed step-ups, reports the lists, and never fails Home for a bad one', async () => {
    const renewedCid = buildStepUp({ key, override: { delegationCid: 'bafyrenewed' } });
    const { fetchFn } = recorder(() => jsonResponse(200, {
      refresh_token: 'rt-2', tinycloud_delegation: home(),
      tinycloud_stepups: [
        renewedCid,
        buildStepUp({ key, signer: stranger, override: { appId: 'xyz.tinycloud.account' } }),
        buildStepUp({ key, override: { appId: 'xyz.tinycloud.courier' } }),
        'not an object',
      ],
      tinycloud_stepups_dropped: ['xyz.tinycloud.account', 'bad id!'],
      tinycloud_stepups_failed: ['xyz.tinycloud.courier'],
      tinycloud_stepups_removed: [APP.replace('explorer', 'old')],
    }));
    const result = await renewDelegation({ ...base, fetchFn });
    expect(result.refreshToken).toBe('rt-2');
    expect(result.stepUps?.renewed.map((stepUp) => stepUp.delegationCid)).toEqual(['bafyrenewed']);
    expect(result.stepUps?.dropped).toEqual(['xyz.tinycloud.account']);
    expect(result.stepUps?.failed).toEqual(['xyz.tinycloud.courier']);
    expect(result.stepUps?.removed).toEqual(['xyz.tinycloud.old']);
    expect(result.stepUps?.rejected.map((rejection) => rejection.appId)).toEqual(['xyz.tinycloud.account', 'xyz.tinycloud.courier', null]);
  });

  it('rejects a renewed step-up for a held app that is tampered or repeated', async () => {
    const { fetchFn } = recorder(() => jsonResponse(200, {
      refresh_token: 'rt-2', tinycloud_delegation: home(),
      tinycloud_stepups: [buildStepUp({ key }), buildStepUp({ key }), buildStepUp({ key, signer: stranger })],
    }));
    const result = await renewDelegation({ ...base, fetchFn });
    expect(result.stepUps?.renewed).toHaveLength(1);
    expect(result.stepUps?.rejected).toHaveLength(2);
  });

  it('treats every step-up as unheld when the caller passes none', async () => {
    const { fetchFn } = recorder(() => jsonResponse(200, { refresh_token: 'rt-2', tinycloud_delegation: home(), tinycloud_stepups: [buildStepUp({ key })] }));
    const result = await renewDelegation({ ...base, heldStepUps: undefined, fetchFn });
    expect(result.stepUps?.renewed).toEqual([]);
    expect(result.stepUps?.rejected).toHaveLength(1);
  });

  const homeFields = ['grantId', 'address', 'chainId', 'renewableUntil'];
  it.each(homeFields)('rejects every renewed step-up, and still renews Home, when Home lacks %s', async (field) => {
    const delegation: Record<string, unknown> = home();
    delete delegation[field];
    const { fetchFn } = recorder(() => jsonResponse(200, { refresh_token: 'rt-2', tinycloud_delegation: delegation, tinycloud_stepups: [buildStepUp({ key })] }));
    const result = await renewDelegation({ ...base, fetchFn });
    expect(result.refreshToken).toBe('rt-2');
    expect(result.stepUps?.renewed).toEqual([]);
    expect(result.stepUps?.rejected).toHaveLength(1);
    expect(result.stepUps?.rejected[0]?.message).toContain(field);
  });

  it('rejects a renewed step-up bound to another chain than Home', async () => {
    const { fetchFn } = recorder(() => jsonResponse(200, { refresh_token: 'rt-2', tinycloud_delegation: { ...home(), chainId: 137 }, tinycloud_stepups: [buildStepUp({ key })] }));
    const result = await renewDelegation({ ...base, fetchFn });
    expect(result.stepUps?.renewed).toEqual([]);
    expect(result.stepUps?.rejected).toHaveLength(1);
  });
});

describe('discovery and app ids', () => {
  const document = {
    issuer: ISSUER,
    authorization_endpoint: `${ORIGIN}/api/auth/oauth2/authorize`,
    token_endpoint: `${ORIGIN}/api/auth/oauth2/token`,
    pushed_authorization_request_endpoint: `${ORIGIN}/api/auth/oauth2/par`,
    tinycloud_delegation_renew_endpoint: `${ORIGIN}/api/auth/oauth2/tinycloud/renew`,
    tinycloud_delegation_revocation_endpoint: `${ORIGIN}/api/auth/oauth2/tinycloud/revoke`,
  };

  it('reads the optional step-up endpoint only when it is on the issuer origin', async () => {
    const advertised = recorder(() => jsonResponse(200, { ...document, tinycloud_delegation_stepup_endpoint: STEP_UP_ENDPOINT }));
    expect((await discoverOpenKeyServer(ISSUER, advertised.fetchFn)).tinycloudDelegationStepUpEndpoint).toBe(STEP_UP_ENDPOINT);
    const absent = recorder(() => jsonResponse(200, document));
    expect('tinycloudDelegationStepUpEndpoint' in await discoverOpenKeyServer(ISSUER, absent.fetchFn)).toBe(false);
    const foreign = recorder(() => jsonResponse(200, { ...document, tinycloud_delegation_stepup_endpoint: 'https://evil.example/stepup' }));
    expect((await discoverOpenKeyServer(ISSUER, foreign.fetchFn)).tinycloudDelegationStepUpEndpoint).toBeUndefined();
  });

  it('accepts only dotted ASCII app ids', () => {
    for (const ok of ['xyz.tinycloud.explorer', 'ab', 'a-b.c9']) expect(isNativeStepUpAppId(ok)).toBe(true);
    for (const bad of ['', 'a', '.a.b', 'a.b.', 'a b', 'a/b', '../x', 'x'.repeat(129), 7, null]) expect(isNativeStepUpAppId(bad)).toBe(false);
  });
});
