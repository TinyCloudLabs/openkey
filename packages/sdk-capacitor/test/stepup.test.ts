import { describe, expect, test } from 'bun:test';
import { base64UrlDecode, sessionDidForPublicKey, type NativeFetch, type NativeFetchResponse, type NativeStepUpPermission } from '@openkey/core';
import { privateKeyToAccount } from 'viem/accounts';
import { OpenKeyNative, type OpenKeyCapacitorPlugin, type TinyCloudDelegation } from '../src/index';

const issuer = 'https://api.openkey.so/api/auth';
const host = 'https://tee.node.tinycloud.xyz';
const redirectUri = 'xyz.tinycloud.exo://openkey/callback';
const stepUpRedirectUri = 'xyz.tinycloud.exo://openkey/stepup';
const explorer = 'xyz.tinycloud.explorer';
const account = 'xyz.tinycloud.account';
const courier = 'xyz.tinycloud.courier';
const owner = privateKeyToAccount(`0x${'1'.padStart(64, '0')}`);
const stranger = privateKeyToAccount(`0x${'2'.padStart(64, '0')}`);
const homeCapabilities = [{ service: 'tinycloud.kv', space: 'applications', path: 'app/threads/', actions: ['tinycloud.kv/get'] }];
const readCapabilities: NativeStepUpPermission[] = [
  { service: 'tinycloud.kv', space: 'public', path: '', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
  { service: 'tinycloud.sql', space: 'applications', path: 'default', actions: ['tinycloud.sql/read'] },
];
interface StepUpEntry { service: string; space: string; path: string; actions: string[] }
type Json = Record<string, unknown>;
interface StepUpOverrides {
  appId?: string;
  signer?: typeof owner;
  permissions?: StepUpEntry[];
  spaces?: string[];
  cid?: string;
  grantId?: string;
  verificationMethod?: string;
}

function response(status: number, data: unknown): NativeFetchResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => data, headers: { get: () => null } };
}

class MockPlugin implements OpenKeyCapacitorPlugin {
  values = new Map<string, string>();
  openOptions: Parameters<OpenKeyCapacitorPlugin['openAuthSession']>[0] | null = null;
  callback: (url: string) => Promise<string> = async () => '';
  async openAuthSession({ url, ...options }: Parameters<OpenKeyCapacitorPlugin['openAuthSession']>[0]): Promise<{ url: string }> { this.openOptions = options; return { url: await this.callback(url) }; }
  async secureStoreGet({ key }: { key: string }): Promise<{ value: string | null }> { return { value: this.values.get(key) ?? null }; }
  async secureStoreSet({ key, value }: { key: string; value: string }): Promise<void> { this.values.set(key, value); }
  async secureStoreRemove({ key }: { key: string }): Promise<void> { this.values.delete(key); }
}

function storedSession(plugin: MockPlugin): [string, string] {
  const entry = [...plugin.values].find(([key]) => key.endsWith(':session'));
  if (!entry) throw new Error('missing stored session');
  return entry;
}

function fixture(options: { advertiseStepUp?: boolean; separateRedirect?: boolean; homeOmits?: string } = {}) {
  const advertiseStepUp = options.advertiseStepUp ?? true;
  const configuredStepUpRedirect = options.separateRedirect === false ? undefined : stepUpRedirectUri;
  const callbackStepUpRedirect = configuredStepUpRedirect ?? redirectUri;
  const plugin = new MockPlugin();
  const renewableUntil = new Date(Date.now() + 30 * 86_400_000).toISOString();
  let keyId = '';
  let signInState = '';
  let stepUpState = '';
  let stepUpApp = '';
  let denyConsent = false;
  const stepUpForms: URLSearchParams[] = [];
  const stepUpHeaders: Array<Record<string, string> | undefined> = [];
  const tokenForms: URLSearchParams[] = [];
  const tokenHeaders: Array<Record<string, string> | undefined> = [];
  const renewForms: URLSearchParams[] = [];
  const revokeForms: URLSearchParams[] = [];

  const delegation = () => {
    const built: Record<string, unknown> = {
      verificationMethod: keyId, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), issuedAt: new Date().toISOString(),
      permissions: [
        { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }, ...homeCapabilities,
      ], tinycloudHost: host, address: owner.address, chainId: 1, grantId: 'grant-1', renewableUntil,
      spaceId: `tinycloud:pkh:eip155:1:${owner.address}:applications`,
      siwe: 'signed siwe', signature: '0xsignature', delegationHeader: { Authorization: 'Bearer fake' }, delegationCid: 'bafyhome',
    };
    if (options.homeOmits) delete built[options.homeOmits];
    return built;
  };

  async function signedStepUp(overrides: StepUpOverrides = {}): Promise<Json> {
    const permissions: StepUpEntry[] = overrides.permissions ?? readCapabilities;
    const spaces = overrides.spaces ?? [...new Set(permissions.map((permission) => permission.space))];
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
    const siwe = [
      'openkey.so wants you to sign in with your Ethereum account:', owner.address, '', 'Delegate read access to a TinyCloud app', '',
      `URI: ${keyId.split('#')[0]}`, 'Version: 1', 'Chain ID: 1', 'Nonce: stepupnonce1', `Issued At: ${issuedAt}`, `Expiration Time: ${expiresAt}`,
    ].join('\n');
    const signature = await (overrides.signer ?? owner).signMessage({ message: siwe });
    return {
      version: 1, appId: overrides.appId ?? stepUpApp, grantId: overrides.grantId ?? 'grant-1', address: owner.address, chainId: 1,
      ownerDid: `did:pkh:eip155:1:${owner.address}`,
      spaces: spaces.map((space) => ({ space, spaceId: `tinycloud:pkh:eip155:1:${owner.address}:${space}` })),
      verificationMethod: overrides.verificationMethod ?? keyId, siwe, signature, delegationHeader: { Authorization: 'Bearer fake' },
      delegationCid: overrides.cid ?? 'bafystepup', issuedAt, expiresAt, renewableUntil, permissions, tinycloudHost: host, hosting: 'existing',
    };
  }

  let stepUpReply: () => NativeFetchResponse = () => response(201, { request_uri: 'urn:stepup:1', expires_in: 90 });
  let exchangeReply: () => Promise<NativeFetchResponse> = async () =>
    response(200, { access_token: 'step-access', token_type: 'Bearer', expires_in: 300, tinycloud_stepup: await signedStepUp() });
  let renewReply: () => Promise<NativeFetchResponse> = async () => response(200, { refresh_token: 'next', tinycloud_delegation: delegation() });
  let revokeReply: () => NativeFetchResponse = () => response(200, {});

  const fetchFn: NativeFetch = async (url, init) => {
    if (url.includes('.well-known')) {
      return response(200, {
        issuer, authorization_endpoint: `${issuer}/oauth2/authorize`, token_endpoint: `${issuer}/oauth2/token`,
        pushed_authorization_request_endpoint: `${issuer}/oauth2/par`,
        tinycloud_delegation_renew_endpoint: `${issuer}/oauth2/tinycloud/renew`,
        tinycloud_delegation_revocation_endpoint: `${issuer}/oauth2/tinycloud/revoke`,
        ...(advertiseStepUp ? { tinycloud_delegation_stepup_endpoint: `${issuer}/oauth2/tinycloud/stepup` } : {}),
      });
    }
    if (url.endsWith('/par')) {
      const form = new URLSearchParams(init?.body);
      signInState = form.get('state')!;
      const detail = JSON.parse(form.get('authorization_details')!)[0];
      const did = sessionDidForPublicKey(base64UrlDecode(detail.session_key.x));
      keyId = `${did}#${did.slice('did:key:'.length)}`;
      return response(201, { request_uri: 'urn:request:1', expires_in: 90 });
    }
    if (url.endsWith('/stepup')) {
      const form = new URLSearchParams(init?.body);
      stepUpForms.push(form);
      stepUpHeaders.push(init?.headers);
      stepUpState = form.get('state')!;
      stepUpApp = form.get('app_id')!;
      return stepUpReply();
    }
    if (url.endsWith('/token')) {
      const form = new URLSearchParams(init?.body);
      tokenForms.push(form);
      tokenHeaders.push(init?.headers);
      if (form.get('code') === 'stepcode') return exchangeReply();
      return response(200, { access_token: 'access', refresh_token: 'initial', tinycloud_delegation: delegation() });
    }
    if (url.endsWith('/renew')) { renewForms.push(new URLSearchParams(init?.body)); return renewReply(); }
    if (url.endsWith('/revoke')) { revokeForms.push(new URLSearchParams(init?.body)); return revokeReply(); }
    throw new Error('unexpected request');
  };
  plugin.callback = async (url) => {
    const requestUri = new URL(url).searchParams.get('request_uri') ?? '';
    const iss = encodeURIComponent(issuer);
    if (requestUri.startsWith('urn:stepup')) {
      return denyConsent
        ? `${callbackStepUpRedirect}?error=access_denied&state=${stepUpState}&iss=${iss}`
        : `${callbackStepUpRedirect}?code=stepcode&state=${stepUpState}&iss=${iss}`;
    }
    return `${redirectUri}?code=code&state=${signInState}&iss=${iss}`;
  };
  const make = (verifyDelegation: (delegation: TinyCloudDelegation) => Promise<void> = async () => {}) =>
    new OpenKeyNative({ clientId: 'exo', redirectUri, ...(configuredStepUpRedirect ? { stepUpRedirectUri: configuredStepUpRedirect } : {}),
      plugin, fetchFn, verifyDelegation, sleepFn: async () => {} });
  return { plugin, make, signedStepUp, stepUpForms, stepUpHeaders, tokenForms, tokenHeaders, renewForms, revokeForms,
    setStepUpReply: (fn: typeof stepUpReply) => { stepUpReply = fn; },
    setExchangeReply: (fn: typeof exchangeReply) => { exchangeReply = fn; },
    setRenewReply: (fn: typeof renewReply) => { renewReply = fn; },
    setRevokeReply: (fn: typeof revokeReply) => { revokeReply = fn; },
    denyConsent: () => { denyConsent = true; },
    homeDelegation: delegation };
}

async function signedIn(options: Parameters<typeof fixture>[0] = {}) {
  const f = fixture(options);
  const client = f.make();
  await client.signIn({ capabilities: homeCapabilities });
  // The sign-in opened the browser itself; what a test asks is whether the step-up did.
  f.plugin.openOptions = null;
  return { f, client };
}

describe('OpenKeyNative step-up', () => {
  test('requests, consents, exchanges and stores a step-up without touching the grant', async () => {
    const { f, client } = await signedIn();
    expect((await client.current())?.stepUps).toBeUndefined();
    const stepUp = await client.requestStepUp({ appId: explorer, capabilities: readCapabilities });
    expect(stepUp).toMatchObject({ appId: explorer, grantId: 'grant-1', hosting: 'existing', delegationCid: 'bafystepup' });

    const form = f.stepUpForms[0]!;
    expect([...form.keys()].sort()).toEqual(['app_id', 'client_id', 'code_challenge', 'code_challenge_method', 'permissions', 'redirect_uri', 'refresh_token', 'state']);
    expect(form.get('refresh_token')).toBe('initial');
    expect(form.get('app_id')).toBe(explorer);
    expect(form.get('redirect_uri')).toBe(stepUpRedirectUri);
    expect(form.get('code_challenge_method')).toBe('S256');
    expect(JSON.parse(form.get('permissions')!)).toEqual(readCapabilities);
    expect(f.stepUpHeaders[0]?.['OpenKey-Session-Proof']).toBeTruthy();
    expect(f.plugin.openOptions?.callbackUrl).toBe(stepUpRedirectUri);

    const exchange = f.tokenForms.at(-1)!;
    expect(exchange.get('code')).toBe('stepcode');
    expect(exchange.get('redirect_uri')).toBe(stepUpRedirectUri);
    expect(exchange.get('code_verifier')).toBeTruthy();
    expect(f.tokenHeaders.at(-1)?.['OpenKey-Session-Proof']).toBeTruthy();

    const current = await client.current();
    expect(current?.stepUps?.[explorer]?.delegationCid).toBe('bafystepup');
    expect(current?.tokens.refreshToken).toBe('initial');
    expect(f.renewForms).toHaveLength(0);
    expect(f.revokeForms).toHaveLength(0);
    // A new process restores the step-up with the session.
    expect((await f.make().current())?.stepUps?.[explorer]?.delegationCid).toBe('bafystepup');
  });

  test('the step-up redirect defaults to the sign-in redirect', async () => {
    const { f, client } = await signedIn({ separateRedirect: false });
    await client.requestStepUp({ appId: explorer, capabilities: readCapabilities });
    expect(f.stepUpForms[0]!.get('redirect_uri')).toBe(redirectUri);
    expect(f.tokenForms.at(-1)!.get('redirect_uri')).toBe(redirectUri);
    expect(f.plugin.openOptions?.callbackUrl).toBe(redirectUri);
  });

  test('a step-up added to a session stored before step-ups keeps its layout', async () => {
    const { f, client } = await signedIn();
    const before = storedSession(f.plugin)[1];
    expect('stepUps' in JSON.parse(before)).toBe(false);
    await client.requestStepUp({ appId: explorer, capabilities: readCapabilities });
    const after = JSON.parse(storedSession(f.plugin)[1]);
    expect(Object.keys(after.stepUps)).toEqual([explorer]);
    delete after.stepUps;
    expect(after).toEqual(JSON.parse(before));
    expect(Object.keys(after).sort()).toEqual([...Object.keys(JSON.parse(before))].sort());
  });

  test('a stored session without step-ups, or with a malformed stepUps member, still loads', async () => {
    const { f } = await signedIn();
    const [key, value] = storedSession(f.plugin);
    expect((await f.make().current())?.delegation.delegationCid).toBe('bafyhome');
    for (const garbage of ['garbage', [], { [explorer]: 'nope', 'not an app': {} }, { [explorer]: { appId: courier } }]) {
      f.plugin.values.set(key, JSON.stringify({ ...JSON.parse(value), stepUps: garbage }));
      const restored = await f.make().current();
      expect(restored?.delegation.delegationCid).toBe('bafyhome');
      expect(restored?.stepUps).toBeUndefined();
    }
  });

  test('an API without step-up fails typed before any request or browser', async () => {
    const { f, client } = await signedIn({ advertiseStepUp: false });
    const before = storedSession(f.plugin)[1];
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(f.stepUpForms).toHaveLength(0);
    expect(f.plugin.openOptions).toBeNull();
    expect(storedSession(f.plugin)[1]).toBe(before);
  });

  const refusals: Array<[string, number, Json, string]> = [
    ['404 not_found', 404, { error: 'not_found' }, 'UNAVAILABLE'],
    ['400 access_denied', 400, { error: 'access_denied' }, 'ACCESS_DENIED'],
    ['400 invalid_request', 400, { error: 'invalid_request' }, 'INVALID_REQUEST'],
    ['400 invalid_authorization_details', 400, { error: 'invalid_authorization_details' }, 'INVALID_REQUEST'],
    ['400 consent_required', 400, { error: 'consent_required' }, 'CONSENT_REQUIRED'],
    ['401 invalid_session_proof', 401, { error: 'invalid_session_proof' }, 'INVALID_GRANT'],
  ];
  test.each(refusals)('a %s refusal degrades with a typed error and leaves the session untouched', async (_name, status, body, code) => {
    const { f, client } = await signedIn();
    const before = storedSession(f.plugin)[1];
    f.setStepUpReply(() => response(status, body));
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code });
    expect(f.plugin.openOptions).toBeNull();
    expect(storedSession(f.plugin)[1]).toBe(before);
    const current = await client.current();
    expect(current?.stepUps).toBeUndefined();
    expect(current?.tokens.refreshToken).toBe('initial');
    // The grant is still renewable afterwards.
    expect((await client.renew()).tokens.refreshToken).toBe('next');
  });

  test('a 429 slow_down is a retryable typed error', async () => {
    const { f, client } = await signedIn();
    f.setStepUpReply(() => ({ ...response(429, { error: 'slow_down' }), headers: { get: () => '10' } }));
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities }))
      .rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE', retryAfterSeconds: 10 });
  });

  test('a denied consent screen is ACCESS_DENIED and leaves the session untouched', async () => {
    const { f, client } = await signedIn();
    const before = storedSession(f.plugin)[1];
    f.denyConsent();
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(f.tokenForms.filter((form) => form.get('code') === 'stepcode')).toHaveLength(0);
    expect(storedSession(f.plugin)[1]).toBe(before);
  });

  test('bad input fails before any request', async () => {
    const { f, client } = await signedIn();
    await expect(client.requestStepUp({ appId: 'not an app', capabilities: readCapabilities })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(client.requestStepUp({ appId: explorer, capabilities: [] })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(client.requestStepUp({ appId: explorer, capabilities: [{ service: 'tinycloud.kv', space: 'public', path: '', actions: ['tinycloud.kv/put'] }] }))
      .rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(client.requestStepUp({ appId: explorer, capabilities: [{ service: 'tinycloud.kv', space: 'secrets' as never, path: '', actions: ['tinycloud.kv/get'] }] }))
      .rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    expect(f.stepUpForms).toHaveLength(0);
  });

  test('needs a session', async () => {
    const f = fixture();
    await expect(f.make().requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    await expect(f.make().revokeStepUp(explorer)).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    const client = f.make();
    await client.signIn({ capabilities: homeCapabilities });
    await client.signOut();
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(f.stepUpForms).toHaveLength(0);
  });

  const tampered: Array<[string, StepUpOverrides]> = [
    ['signed by another account', { signer: stranger }],
    ['carrying a space that was not requested', {
      permissions: [...readCapabilities, { service: 'tinycloud.kv', space: 'agents', path: 'x/', actions: ['tinycloud.kv/get'] }],
    }],
    ['listing other spaces than its permissions', { spaces: ['public'] }],
    ['for another app', { appId: courier }],
    ['carrying a write action', { permissions: [{ ...readCapabilities[0]!, actions: ['tinycloud.kv/put'] }] }],
    ['bound to another grant', { grantId: 'grant-2' }],
    ['delegated to another key', { verificationMethod: 'did:key:z6MkOther#z6MkOther' }],
  ];
  test.each(tampered)('rejects a step-up %s and leaves the session untouched', async (_name, overrides) => {
    const { f, client } = await signedIn();
    const before = storedSession(f.plugin)[1];
    f.setExchangeReply(async () => response(200, { tinycloud_stepup: await f.signedStepUp(overrides) }));
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'SERVER' });
    expect(storedSession(f.plugin)[1]).toBe(before);
    expect((await client.current())?.stepUps).toBeUndefined();
  });

  test('rejects a step-up response that carries a refresh token or a grant', async () => {
    for (const extra of [{ refresh_token: 'rogue' }, { tinycloud_delegation: { expiresAt: 1 } }]) {
      const { f, client } = await signedIn();
      const before = storedSession(f.plugin)[1];
      f.setExchangeReply(async () => response(200, { ...extra, tinycloud_stepup: await f.signedStepUp() }));
      await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'SERVER' });
      expect(storedSession(f.plugin)[1]).toBe(before);
    }
  });

  test('a step-up the TinyCloud verifier refuses is not stored', async () => {
    const f = fixture();
    const client = f.make(async (delegation) => { if (delegation.delegationCid === 'bafystepup') throw new Error('bad cid'); });
    await client.signIn({ capabilities: homeCapabilities });
    const before = storedSession(f.plugin)[1];
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'SERVER' });
    expect(storedSession(f.plugin)[1]).toBe(before);
  });

  test('a failed code exchange is typed and leaves the session untouched', async () => {
    const { f, client } = await signedIn();
    const before = storedSession(f.plugin)[1];
    f.setExchangeReply(async () => response(400, { error: 'invalid_grant' }));
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'INVALID_GRANT' });
    expect(storedSession(f.plugin)[1]).toBe(before);
    expect((await client.current())?.tokens.refreshToken).toBe('initial');
  });

  test.each(['grantId', 'address', 'chainId', 'renewableUntil'])('refuses a step-up before asking the user when Home lacks %s', async (field) => {
    const { f, client } = await signedIn({ homeOmits: field });
    const before = storedSession(f.plugin)[1];
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'SERVER' });
    expect(f.stepUpForms).toHaveLength(0);
    expect(f.plugin.openOptions).toBeNull();
    expect(f.revokeForms).toHaveLength(0);
    expect(storedSession(f.plugin)[1]).toBe(before);
    expect((await client.current())?.stepUps).toBeUndefined();
  });

  test('an exchanged but invalid step-up is revoked for that app and the original error is kept', async () => {
    const { f, client } = await signedIn();
    const before = storedSession(f.plugin)[1];
    f.setExchangeReply(async () => response(200, { tinycloud_stepup: await f.signedStepUp({ signer: stranger }) }));
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'SERVER' });
    expect(f.revokeForms).toHaveLength(1);
    expect(f.revokeForms[0]!.get('app_id')).toBe(explorer);
    expect(f.revokeForms[0]!.get('refresh_token')).toBe('initial');
    expect(storedSession(f.plugin)[1]).toBe(before);
  });

  test('a failing cleanup revoke never masks the original error', async () => {
    const { f, client } = await signedIn();
    f.setExchangeReply(async () => response(200, { tinycloud_stepup: await f.signedStepUp({ signer: stranger }) }));
    f.setRevokeReply(() => response(400, { error: 'invalid_request' }));
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'SERVER', message: expect.stringContaining('signature') });
    expect(f.revokeForms).toHaveLength(1);
    f.setRevokeReply(() => { throw new Error('network down'); });
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'SERVER' });
    expect((await client.current())?.tokens.refreshToken).toBe('initial');
  });

  test('a step-up the verifier refuses is revoked and nothing is stored', async () => {
    const f = fixture();
    const client = f.make(async (delegation) => { if (delegation.delegationCid === 'bafystepup') throw new Error('bad cid'); });
    await client.signIn({ capabilities: homeCapabilities });
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'SERVER' });
    expect(f.revokeForms.map((form) => form.get('app_id'))).toEqual([explorer]);
    expect((await client.current())?.stepUps).toBeUndefined();
  });

  test('a refused new step-up also drops the copy this app held before', async () => {
    const { f, client } = await signedIn();
    await client.requestStepUp({ appId: explorer, capabilities: readCapabilities });
    await client.requestStepUp({ appId: courier, capabilities: readCapabilities });
    f.setExchangeReply(async () => response(200, { tinycloud_stepup: await f.signedStepUp({ signer: stranger }) }));
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'SERVER' });
    expect(f.revokeForms.map((form) => form.get('app_id'))).toEqual([explorer]);
    expect(Object.keys((await client.current())?.stepUps ?? {})).toEqual([courier]);
  });

  test('a server refusal of the exchange, or a declined consent, creates nothing to revoke', async () => {
    const { f, client } = await signedIn();
    f.setExchangeReply(async () => response(400, { error: 'invalid_grant' }));
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'INVALID_GRANT' });
    f.denyConsent();
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(f.revokeForms).toHaveLength(0);
  });

  async function withStepUps(apps: string[]) {
    const ready = await signedIn();
    for (const appId of apps) await ready.client.requestStepUp({ appId, capabilities: readCapabilities });
    return ready;
  }

  test('renewal merges renewed step-ups, removes ended ones and keeps a rejected one as it was', async () => {
    const { f, client } = await withStepUps([explorer, account, courier]);
    f.setRenewReply(async () => response(200, {
      refresh_token: 'next', tinycloud_delegation: f.homeDelegation(),
      tinycloud_stepups: [
        await f.signedStepUp({ appId: explorer, cid: 'bafyrenewed' }),
        // Signed by the wrong account: rejected, never fails Home's renewal.
        await f.signedStepUp({ appId: courier, cid: 'bafytampered', signer: stranger }),
        // An app this session holds nothing for.
        await f.signedStepUp({ appId: 'xyz.tinycloud.other', cid: 'bafyunknown' }),
      ],
      tinycloud_stepups_removed: [account],
    }));
    const renewed = await client.renew();
    expect(renewed.tokens.refreshToken).toBe('next');
    expect(renewed.delegation.delegationCid).toBe('bafyhome');
    expect(Object.keys(renewed.stepUps ?? {}).sort()).toEqual([courier, explorer]);
    expect(renewed.stepUps?.[explorer]?.delegationCid).toBe('bafyrenewed');
    expect(renewed.stepUps?.[courier]?.delegationCid).toBe('bafystepup');
    expect((await f.make().current())?.stepUps?.[explorer]?.delegationCid).toBe('bafyrenewed');
    expect(f.renewForms.at(-1)?.has('app_id')).toBe(false);
  });

  test('renewal keeps dropped and failed step-ups as they were', async () => {
    const { f, client } = await withStepUps([explorer, courier]);
    f.setRenewReply(async () => response(200, {
      refresh_token: 'next', tinycloud_delegation: f.homeDelegation(), tinycloud_stepups: [],
      tinycloud_stepups_dropped: [explorer], tinycloud_stepups_failed: [courier],
    }));
    const renewed = await client.renew();
    expect(renewed.tokens.refreshToken).toBe('next');
    expect(Object.keys(renewed.stepUps ?? {}).sort()).toEqual([courier, explorer]);
    expect(renewed.stepUps?.[explorer]?.delegationCid).toBe('bafystepup');
    expect(renewed.stepUps?.[courier]?.delegationCid).toBe('bafystepup');
  });

  test('a renewal that removes the last step-up leaves a session without a stepUps member', async () => {
    const { f, client } = await withStepUps([explorer]);
    f.setRenewReply(async () => response(200, {
      refresh_token: 'next', tinycloud_delegation: f.homeDelegation(), tinycloud_stepups: [], tinycloud_stepups_removed: [explorer],
    }));
    expect((await client.renew()).stepUps).toBeUndefined();
    expect('stepUps' in JSON.parse(storedSession(f.plugin)[1])).toBe(false);
  });

  test('a renewal without step-up fields leaves the held ones alone', async () => {
    const { client } = await withStepUps([explorer]);
    const renewed = await client.renew();
    expect(renewed.tokens.refreshToken).toBe('next');
    expect(renewed.stepUps?.[explorer]?.delegationCid).toBe('bafystepup');
  });

  test('a renewal racing a step-up request keeps both the rotated token and the step-up', async () => {
    const { f, client } = await signedIn();
    const [stepUp, renewed] = await Promise.all([
      client.requestStepUp({ appId: explorer, capabilities: readCapabilities }),
      client.renew(),
    ]);
    expect(stepUp.appId).toBe(explorer);
    expect(renewed.tokens.refreshToken).toBe('next');
    const stored = JSON.parse(storedSession(f.plugin)[1]);
    expect(stored.tokens.refreshToken).toBe('next');
    expect(Object.keys(stored.stepUps)).toEqual([explorer]);
  });

  test('a second concurrent request for the same app is refused while the first runs', async () => {
    const { client } = await signedIn();
    const first = client.requestStepUp({ appId: explorer, capabilities: readCapabilities });
    await expect(client.requestStepUp({ appId: explorer, capabilities: readCapabilities })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    await first;
  });

  test('revokeStepUp ends one app on the server and drops only its local copy', async () => {
    const { f, client } = await withStepUps([explorer, courier]);
    await client.revokeStepUp(explorer);
    const form = f.revokeForms[0]!;
    expect(form.get('app_id')).toBe(explorer);
    expect(form.get('refresh_token')).toBe('initial');
    expect(form.get('client_id')).toBe('exo');
    const current = await client.current();
    expect(Object.keys(current?.stepUps ?? {})).toEqual([courier]);
    expect(current?.tokens.refreshToken).toBe('initial');
    // An app with no step-up still reaches the server, which answers 200.
    await client.revokeStepUp(account);
    expect(f.revokeForms[1]!.get('app_id')).toBe(account);
    await client.revokeStepUp(courier);
    expect((await client.current())?.stepUps).toBeUndefined();
    expect('stepUps' in JSON.parse(storedSession(f.plugin)[1])).toBe(false);
  });

  test('a refused revokeStepUp is typed and keeps the local step-up', async () => {
    const { f, client } = await withStepUps([explorer]);
    f.setRevokeReply(() => response(400, { error: 'invalid_request' }));
    await expect(client.revokeStepUp(explorer)).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    expect((await client.current())?.stepUps?.[explorer]?.delegationCid).toBe('bafystepup');
    await expect(client.revokeStepUp('not an app')).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });

  test('signOut revokes the grant and clears the step-ups with the session', async () => {
    const { f, client } = await withStepUps([explorer, courier]);
    await client.signOut();
    expect(f.revokeForms).toHaveLength(1);
    expect(f.revokeForms[0]!.has('app_id')).toBe(false);
    expect(await client.current()).toBeNull();
    expect([...f.plugin.values.keys()].some((key) => key.endsWith(':session'))).toBe(false);
    expect(await f.make().current()).toBeNull();
  });
});
