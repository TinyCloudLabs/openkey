import { describe, expect, test } from 'bun:test';
import { base64UrlDecode, sessionDidForPublicKey, type NativeFetch, type NativeFetchResponse } from '@openkey/core';
import { OpenKeyCapacitor, OpenKeyNative, OpenKeyNativeError, type NativeSession, type OpenKeyCapacitorPlugin } from '../src/index';

const issuer = 'https://api.openkey.so/api/auth';
const host = 'https://tee.node.tinycloud.xyz';
const redirectUri = 'xyz.tinycloud.exo://openkey/callback';
const capabilities = [{ service: 'tinycloud.kv', space: 'applications', path: 'app/threads/', actions: ['tinycloud.kv/get'] }];
const persisted = (session: NativeSession) => ({ address: session.delegation.address!, sessionKey: JSON.stringify(session.sessionKey.privateJwk) }) as never;
function sessionEntry(plugin: MockPlugin): [string, string] {
  const entry = [...plugin.values].find(([key]) => key.endsWith(':session'));
  if (!entry) throw new Error('missing stored session');
  return entry;
}

function response(status: number, data: unknown, retryAfter?: string): NativeFetchResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => data,
    headers: { get: () => retryAfter ?? null } };
}

async function eventually(check: () => boolean): Promise<void> {
  for (let i = 0; i < 50 && !check(); i++) await new Promise((resolve) => setTimeout(resolve, 0));
  expect(check()).toBe(true);
}

class MockPlugin implements OpenKeyCapacitorPlugin {
  values = new Map<string, string>();
  failSet = false;
  failGet = false;
  failRemove = false;
  setCount = 0;
  callback: (url: string) => Promise<string> = async () => '';
  async openAuthSession({ url }: { url: string }): Promise<{ url: string }> { return { url: await this.callback(url) }; }
  async secureStoreGet({ key }: { key: string }): Promise<{ value: string | null }> { if (this.failGet) throw new Error('decrypt'); return { value: this.values.get(key) ?? null }; }
  async secureStoreSet({ key, value }: { key: string; value: string }): Promise<void> { this.setCount++; if (this.failSet) throw new Error('write'); this.values.set(key, value); }
  async secureStoreRemove({ key }: { key: string }): Promise<void> { if (this.failRemove) throw new Error('wipe'); this.values.delete(key); }
}

function fixture(approved = capabilities) {
  const plugin = new MockPlugin();
  let state = '';
  let keyId = '';
  let renewCalls = 0;
  let revokeCalls = 0;
  const revokeTokens: string[] = [];
  const renewTokens: string[] = [];
  const requestLog: string[] = [];
  let immediateRenewal = false;
  let tokenReply: () => NativeFetchResponse = () => response(200, { access_token: 'access', refresh_token: 'initial', tinycloud_delegation: delegation() });
  let renewReply: (call: number) => NativeFetchResponse = () => response(200, renewal('next'));
  let revokeReply: () => NativeFetchResponse | Promise<NativeFetchResponse> = () => response(200, {});
  let discoveryReply: () => NativeFetchResponse = () => response(200, {
    issuer, authorization_endpoint: `${issuer}/oauth2/authorize`, token_endpoint: `${issuer}/oauth2/token`,
    pushed_authorization_request_endpoint: `${issuer}/oauth2/par`,
    tinycloud_delegation_renew_endpoint: `${issuer}/oauth2/tinycloud/renew`,
    tinycloud_delegation_revocation_endpoint: `${issuer}/oauth2/tinycloud/revoke`,
  });
  const delegation = (granted = approved) => ({
    verificationMethod: keyId, expiresAt: new Date(Date.now() + (immediateRenewal ? 30_000 : 3_600_000)).toISOString(),
    issuedAt: new Date(Date.now() - (immediateRenewal ? 3_600_000 : 0)).toISOString(), permissions: [
      { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }, ...granted,
    ], tinycloudHost: host, address: '0x0000000000000000000000000000000000000001', chainId: 1,
    spaceId: 'tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:applications',
    siwe: 'signed siwe', signature: '0xsignature', delegationHeader: { Authorization: 'Bearer fake' }, delegationCid: 'bafyfake',
  });
  const renewal = (refreshToken: string, granted = approved) => ({ refresh_token: refreshToken, tinycloud_delegation: delegation(granted) });
  const fetchFn: NativeFetch = async (url, init) => {
    requestLog.push(url);
    if (url.includes('.well-known')) return discoveryReply();
    if (url.endsWith('/par')) {
      const form = new URLSearchParams(init?.body);
      state = form.get('state')!;
      const detail = JSON.parse(form.get('authorization_details')!)[0];
      const did = sessionDidForPublicKey(base64UrlDecode(detail.session_key.x));
      keyId = `${did}#${did.slice('did:key:'.length)}`;
      return response(201, { request_uri: 'urn:request:1', expires_in: 90 });
    }
    if (url.endsWith('/token')) return tokenReply();
    if (url.endsWith('/renew')) {
      renewTokens.push(new URLSearchParams(init?.body).get('refresh_token') ?? '');
      return renewReply(++renewCalls);
    }
    if (url.endsWith('/revoke')) {
      revokeCalls++;
      revokeTokens.push(new URLSearchParams(init?.body).get('refresh_token') ?? '');
      return revokeReply();
    }
    throw new Error('unexpected request');
  };
  plugin.callback = async () => `${redirectUri}?code=code&state=${state}&iss=${encodeURIComponent(issuer)}`;
  const make = (verifyDelegation: (delegation: ReturnType<typeof delegation>) => Promise<void> = async () => {}) =>
    new OpenKeyNative({ clientId: 'exo', redirectUri, plugin, fetchFn, verifyDelegation, sleepFn: async () => {} });
  return { plugin, make, delegation, renewal, revokeTokens, renewTokens, requestLog, get state() { return state; }, get renewCalls() { return renewCalls; }, get revokeCalls() { return revokeCalls; },
    setRenewReply: (fn: typeof renewReply) => { renewReply = fn; }, setRevokeReply: (fn: typeof revokeReply) => { revokeReply = fn; },
    setDiscoveryReply: (fn: typeof discoveryReply) => { discoveryReply = fn; },
    setImmediateRenewal: () => { immediateRenewal = true; }, setTokenReply: (fn: typeof tokenReply) => { tokenReply = fn; } };
}

describe('OpenKeyNative', () => {
  test('web fallback reports UNAVAILABLE', async () => {
    await expect(OpenKeyCapacitor.openAuthSession({ url: `${issuer}/oauth2/authorize`, callbackScheme: 'xyz.tinycloud.exo' }))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
  });
  test('signs in, verifies before storing, and restores offline', async () => {
    const f = fixture();
    const client = f.make();
    const session = await client.signIn({ capabilities });
    expect(session.tokens.refreshToken).toBe('initial');
    expect(session.sessionKey.privateJwk.d).toBeTruthy();
    expect((await f.make().current())?.delegation.delegationCid).toBe('bafyfake');
    expect((await client.getSessionKey())?.did).toBe(session.sessionKey.did);
  });

  test('revokes an exchanged grant if TinyCloud verification fails before storage', async () => {
    const f = fixture();
    const client = f.make(async () => { throw new OpenKeyNativeError('SERVER', 'integrity failure'); });
    await expect(client.signIn({ capabilities })).rejects.toMatchObject({ code: 'SERVER' });
    expect(f.revokeCalls).toBe(1);
    expect(await client.current()).toBeNull();
  });

  test('maps cancel, access_denied, and state mismatch', async () => {
    for (const code of ['USER_CANCELLED', 'ACCESS_DENIED', 'STATE_MISMATCH'] as const) {
      const f = fixture();
      f.plugin.callback = code === 'USER_CANCELLED'
        ? async () => { throw { code: 'USER_CANCELLED' }; }
        : code === 'ACCESS_DENIED'
          ? async () => `${redirectUri}?error=access_denied&state=${f.state}&iss=${encodeURIComponent(issuer)}`
          : async () => `${redirectUri}?code=x&state=wrong&iss=${encodeURIComponent(issuer)}`;
      try { await f.make().signIn({ capabilities }); throw new Error('expected failure'); }
      catch (error) { expect(error).toBeInstanceOf(OpenKeyNativeError); expect((error as OpenKeyNativeError).code).toBe(code); }
    }
  });

  test('renew is single-flight and persists rotation', async () => {
    const f = fixture(); const client = f.make();
    await client.signIn({ capabilities });
    const [a, b] = await Promise.all([client.renew(), client.renew()]);
    expect(a.tokens.refreshToken).toBe('next');
    expect(b.tokens.refreshToken).toBe('next');
    expect(f.renewCalls).toBe(1);
    expect((await f.make().current())?.tokens.refreshToken).toBe('next');
  });

  test('renew single-flight uses normalized permissions including capabilities/read', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const read = { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] };
    const first = client.renew({ capabilities });
    const equivalent = client.renew({ capabilities: [...capabilities, read] });
    expect(first).toBe(equivalent);
    await first;
    expect(f.renewCalls).toBe(1);
  });

  test('a subset renew preserves the approved set for a later plain renew', async () => {
    const second = { service: 'tinycloud.kv', space: 'applications', path: 'app/files/', actions: ['tinycloud.kv/get'] };
    const approved = [...capabilities, second];
    const f = fixture(approved); const client = f.make();
    await client.signIn({ capabilities: approved });
    f.setRenewReply((call) => response(200, f.renewal(`rotated${call}`, call === 1 ? capabilities : approved)));
    expect((await client.renew({ capabilities })).tokens.refreshToken).toBe('rotated1');
    expect((await client.renew()).tokens.refreshToken).toBe('rotated2');
    expect(f.renewCalls).toBe(2);
    const stored = JSON.parse([...f.plugin.values].find(([key]) => key.endsWith(':session'))![1]);
    expect(stored.permissions).toEqual(expect.arrayContaining(approved));
  });

  test('keeps a rotated token when post-2xx delegation validation fails', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply(() => response(200, { refresh_token: 'rotated', tinycloud_delegation: { ...f.delegation(), verificationMethod: 'wrong' } }));
    await expect(client.renew()).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'rotated' });
    expect((await f.make().current())?.tokens.refreshToken).toBe('rotated');
  });

  test('reloads after renewal_conflict and retries with the newer token', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply((call) => {
      if (call === 1) {
        for (const [key, value] of f.plugin.values) {
          if (key.endsWith(':session')) {
            const record = JSON.parse(value); record.tokens.refreshToken = 'other';
            f.plugin.values.set(key, JSON.stringify(record));
          }
        }
        return response(409, { error: 'renewal_conflict' });
      }
      return response(200, f.renewal('next'));
    });
    expect((await client.renew()).tokens.refreshToken).toBe('next');
    expect(f.renewCalls).toBe(2);
  });

  test('core obeys Retry-After for 429 and retries once', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply((call) => call === 1 ? response(429, { error: 'renewal_too_soon' }, '1') : response(200, f.renewal('next')));
    expect((await client.renew()).tokens.refreshToken).toBe('next');
    expect(f.renewCalls).toBe(2);
  });

  test('signOut wipes OpenKey and TinyCloud state after terminal revoke failure', async () => {
    const f = fixture(); const client = f.make(); const session = await client.signIn({ capabilities });
    await client.sessionStorageAdapter().save(session.delegation.address!, persisted(session));
    f.setRevokeReply(() => response(401, { error: 'invalid_session_proof' }));
    await client.signOut();
    expect(await client.current()).toBeNull();
    expect(await client.sessionStorageAdapter().load(session.delegation.address!)).toBeNull();
  });

  test('TinyCloud storage adapter never accesses localStorage', async () => {
    const f = fixture(); const client = f.make(); const session = await client.signIn({ capabilities }); const storage = client.sessionStorageAdapter();
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
    Object.defineProperty(globalThis, 'localStorage', { configurable: true, get() { throw new Error('localStorage touched'); } });
    try {
      await storage.save(session.delegation.address!, persisted(session));
      expect((await storage.load(session.delegation.address!))?.sessionKey).toBe(JSON.stringify(session.sessionKey.privateJwk));
      expect(storage.exists(session.delegation.address!)).toBe(true);
      await storage.clear(session.delegation.address!);
      expect(storage.exists(session.delegation.address!)).toBe(false);
    } finally {
      if (previous) Object.defineProperty(globalThis, 'localStorage', previous);
      else Reflect.deleteProperty(globalThis, 'localStorage');
    }
  });

  test('offline current binds the restored session for a secure TinyCloud handoff', async () => {
    const first = fixture();
    await first.make().signIn({ capabilities });
    const restoredApp = fixture();
    restoredApp.plugin.values = new Map(first.plugin.values);
    const client = restoredApp.make();
    const restored = await client.current();
    expect(restored).not.toBeNull();
    await client.sessionStorageAdapter().save(restored!.delegation.address!, persisted(restored!));
    expect((await client.sessionStorageAdapter().load(restored!.delegation.address!))?.sessionKey)
      .toBe(JSON.stringify(restored!.sessionKey.privateJwk));
  });

  test('UNIMPLEMENTED maps to UNAVAILABLE and concurrent authorization has a distinct message', async () => {
    const f = fixture();
    f.plugin.callback = async () => { throw { code: 'UNIMPLEMENTED' }; };
    await expect(f.make().signIn({ capabilities })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    f.plugin.callback = async () => { throw { code: 'ALREADY_IN_PROGRESS' }; };
    await expect(f.make().signIn({ capabilities })).rejects.toMatchObject({ code: 'UNAVAILABLE', message: 'An authorization session is already in progress' });
  });

  test('failed rotation write reports the live token', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.plugin.failSet = true;
    await expect(client.renew()).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'next' });
  });

  test('post-2xx validation error retains its token when persistence also fails', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply(() => response(200, { refresh_token: 'rotated', tinycloud_delegation: { ...f.delegation(), verificationMethod: 'wrong' } }));
    f.plugin.failSet = true;
    await expect(client.renew()).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'rotated' });
  });

  test('verifier rejection after renew keeps the rotated token', async () => {
    const f = fixture(); let verifications = 0;
    const client = f.make(async () => { if (++verifications === 2) throw new Error('bad wasm'); });
    await client.signIn({ capabilities });
    await expect(client.renew()).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'next' });
    expect((await client.current())?.tokens.refreshToken).toBe('next');
  });

  test('terminal renew clears the session', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply(() => response(401, { error: 'invalid_grant' }));
    await expect(client.renew()).rejects.toMatchObject({ code: 'INVALID_GRANT' });
    expect(await client.current()).toBeNull();
  });

  test('terminal post-rotation renew revokes the grant and never persists it', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const writesBefore = f.plugin.setCount;
    f.setRenewReply(() => response(200, { refresh_token: 'rotated', tinycloud_delegation: { ...f.delegation(), hosting: 'failed' } }));
    await expect(client.renew()).rejects.toMatchObject({ code: 'SPACE_UNAVAILABLE' });
    expect(f.revokeTokens).toContain('rotated');
    expect(f.plugin.setCount).toBe(writesBefore);
    expect(await client.current()).toBeNull();
    await expect(client.renew()).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(f.plugin.values.size).toBe(0);
  });

  test('terminal renew still wipes when best-effort rotated revoke stays transient', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply(() => response(200, { refresh_token: 'rotated', tinycloud_delegation: { ...f.delegation(), hosting: 'failed' } }));
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(client.renew()).rejects.toMatchObject({ code: 'SPACE_UNAVAILABLE', rotatedRefreshToken: 'rotated' });
    expect(f.revokeTokens).toEqual(['initial', 'initial', 'rotated', 'rotated']);
    const pending = JSON.parse([...f.plugin.values].find(([key]) => key.endsWith(':pending-revoke'))![1]);
    expect(pending.grants.map((grant: { refreshToken: string }) => grant.refreshToken).sort()).toEqual(['initial', 'rotated']);
    expect(await client.current()).toBeNull();
  });

  test('terminal cleanup cannot wipe a signIn started during rotated-grant revoke', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply(() => response(200, { refresh_token: 'rotated', tinycloud_delegation: { ...f.delegation(), hosting: 'failed' } }));
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.setRevokeReply(async () => { entered(); await gate; return response(200, {}); });
    const terminal = client.renew();
    await started;
    const freshPending = client.signIn({ capabilities });
    release();
    await expect(terminal).rejects.toMatchObject({ code: 'SPACE_UNAVAILABLE' });
    const fresh = await freshPending;
    expect((await client.current())?.sessionKey.did).toBe(fresh.sessionKey.did);
  });

  test('different renew options serialize instead of sharing a flight', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply((call) => response(200, f.renewal(`next${call}`)));
    const [first, second] = await Promise.all([client.renew({ siweNonce: 'nonce0001' }), client.renew({ siweNonce: 'nonce0002' })]);
    expect(first.tokens.refreshToken).toBe('next1');
    expect(second.tokens.refreshToken).toBe('next2');
    expect(f.renewCalls).toBe(2);
  });

  test('a renew resolving after signOut cannot restore the wiped session', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.setRenewReply(() => ({ ...response(200, f.renewal('late')), json: async () => { entered(); await gate; return f.renewal('late'); } }));
    const renewal = client.renew(); await started;
    await client.signOut();
    release();
    await expect(renewal).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(await client.current()).toBeNull();
  });

  test('signOut revokes a replacement stored while the prior revoke is in flight', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const replacement = fixture();
    replacement.setTokenReply(() => response(200, { access_token: 'access-b', refresh_token: 'second', tinycloud_delegation: replacement.delegation() }));
    await replacement.make().signIn({ capabilities });
    const [key, value] = sessionEntry(replacement.plugin);
    f.setRevokeReply(async () => {
      if (f.revokeCalls === 1) f.plugin.values.set(key, value);
      return response(200, {});
    });
    await client.signOut();
    expect(f.revokeTokens).toEqual(['initial', 'second']);
    expect(f.plugin.values.size).toBe(0);
  });

  test('signIn revokes the session it replaces and queues transient failure', async () => {
    const f = fixture(); const client = f.make(); const old = await client.signIn({ capabilities });
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    const fresh = await client.signIn({ capabilities });
    expect(fresh.sessionKey.did).not.toBe(old.sessionKey.did);
    expect(f.revokeTokens).toEqual(['initial', 'initial']);
    const pending = JSON.parse([...f.plugin.values].find(([key]) => key.endsWith(':pending-revoke'))![1]);
    expect(pending.grants.map((grant: { refreshToken: string }) => grant.refreshToken)).toEqual(['initial']);
    expect((await client.current())?.sessionKey.did).toBe(fresh.sessionKey.did);
  });

  test('signOut during a replacement secure-store set revokes both grants', async () => {
    const f = fixture(); const client = f.make();
    let exchanges = 0;
    f.setTokenReply(() => response(200, { access_token: 'access',
      refresh_token: ++exchanges === 1 ? 'initial' : 'second', tinycloud_delegation: f.delegation() }));
    await client.signIn({ capabilities });
    const originalSet = f.plugin.secureStoreSet.bind(f.plugin);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    let blocked = false;
    f.plugin.secureStoreSet = async (item) => {
      await originalSet(item);
      if (item.key.endsWith(':session') && !blocked) { blocked = true; entered(); await gate; }
    };
    const replacement = client.signIn({ capabilities });
    await started;
    const signOut = client.signOut();
    release();
    await expect(replacement).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    await signOut;
    expect(f.revokeTokens).toContain('initial');
    expect(f.revokeTokens).toContain('second');
    expect(f.plugin.values.size).toBe(0);
  });

  test('a rotated-token recovery write cannot replace another stored session', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const replacement = fixture();
    replacement.setTokenReply(() => response(200, { access_token: 'access-b', refresh_token: 'second', tinycloud_delegation: replacement.delegation() }));
    const sessionB = await replacement.make().signIn({ capabilities });
    const [key, value] = sessionEntry(replacement.plugin);
    const invalid = { refresh_token: 'rotated', tinycloud_delegation: { ...f.delegation(), verificationMethod: 'wrong' } };
    f.setRenewReply(() => ({ ...response(200, invalid), json: async () => {
      f.plugin.values.set(key, value);
      return invalid;
    } }));
    await expect(client.renew()).rejects.toMatchObject({ code: 'SERVER' });
    expect(f.revokeTokens).toContain('rotated');
    expect((await client.current())?.sessionKey.did).toBe(sessionB.sessionKey.did);
    expect((await client.current())?.tokens.refreshToken).toBe('second');
  });

  test('a successful old renew cannot overwrite a replacement session', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const replacement = fixture();
    replacement.setTokenReply(() => response(200, { access_token: 'access-b', refresh_token: 'second', tinycloud_delegation: replacement.delegation() }));
    const sessionB = await replacement.make().signIn({ capabilities });
    const [key, value] = sessionEntry(replacement.plugin);
    const oldRenewal = f.renewal('rotated');
    f.setRenewReply(() => ({ ...response(200, oldRenewal), json: async () => {
      f.plugin.values.set(key, value);
      return oldRenewal;
    } }));
    await expect(client.renew()).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(f.revokeTokens).toContain('rotated');
    expect((await client.current())?.sessionKey.did).toBe(sessionB.sessionKey.did);
    expect((await client.current())?.tokens.refreshToken).toBe('second');
  });

  test('a superseded renew queues its rotated token after transient revoke failure', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const oldRenewal = f.renewal('rotated');
    f.setRenewReply(() => ({ ...response(200, oldRenewal), json: async () => { entered(); await gate; return oldRenewal; } }));
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    const renewal = client.renew();
    await started;
    await expect(client.signOut()).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE' });
    release();
    await expect(renewal).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    const pending = JSON.parse([...f.plugin.values].find(([key]) => key.endsWith(':pending-revoke'))![1]);
    expect(pending.grants.map((grant: { refreshToken: string }) => grant.refreshToken).sort()).toEqual(['initial', 'rotated']);
    expect(await client.current()).toBeNull();
  });

  test('an older sign-in cannot overwrite a replacement stored before its exchange commits', async () => {
    const f = fixture(); const client = f.make();
    const replacement = fixture();
    replacement.setTokenReply(() => response(200, { access_token: 'access-b', refresh_token: 'second', tinycloud_delegation: replacement.delegation() }));
    const sessionB = await replacement.make().signIn({ capabilities });
    const [key, value] = sessionEntry(replacement.plugin);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.plugin.callback = async () => { entered(); await gate; return `${redirectUri}?code=code&state=${f.state}&iss=${encodeURIComponent(issuer)}`; };
    const old = client.signIn({ capabilities });
    await started;
    f.plugin.values.set(key, value);
    release();
    await expect(old).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(f.revokeTokens).toContain('initial');
    expect((await client.current())?.sessionKey.did).toBe(sessionB.sessionKey.did);
  });

  test('an older sign-in immediate renew settles before a replacement sign-in starts', async () => {
    const f = fixture(); f.setImmediateRenewal(); const client = f.make();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.setRenewReply(() => {
      const oldRenewal = f.renewal('old-rotated');
      return { ...response(200, oldRenewal), json: async () => { entered(); await gate; return oldRenewal; } };
    });
    const old = client.signIn({ capabilities });
    await started;
    await client.signOut();
    await expect(client.signIn({ capabilities })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    release();
    await expect(old).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    f.setRenewReply(() => response(200, f.renewal('new-rotated')));
    const fresh = await client.signIn({ capabilities });
    expect((await client.current())?.sessionKey.did).toBe(fresh.sessionKey.did);
    expect((await client.current())?.tokens.refreshToken).toBe('new-rotated');
  });

  test('a delayed read of A does not make a later renew use A after B is stored', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const replacement = fixture();
    replacement.setTokenReply(() => response(200, { access_token: 'access-b', refresh_token: 'second', tinycloud_delegation: replacement.delegation() }));
    await replacement.make().signIn({ capabilities });
    const [key, value] = sessionEntry(replacement.plugin);
    const originalGet = f.plugin.secureStoreGet.bind(f.plugin);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    let delayed = false;
    f.plugin.secureStoreGet = async (args) => {
      if (args.key === key && !delayed) {
        delayed = true;
        const stale = await originalGet(args);
        entered();
        await gate;
        return stale;
      }
      return originalGet(args);
    };
    const oldRead = client.current();
    await started;
    f.plugin.values.set(key, value);
    release();
    await oldRead;
    f.setRenewReply(() => response(200, replacement.renewal('third')));
    expect((await client.renew()).tokens.refreshToken).toBe('third');
    expect(f.renewTokens).toEqual(['second']);
  });

  test('a signOut read failing after it starts leaves the session usable', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const [key] = sessionEntry(f.plugin);
    const originalGet = f.plugin.secureStoreGet.bind(f.plugin);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.plugin.secureStoreGet = async (args) => {
      if (args.key === key) { entered(); await gate; throw new Error('decrypt'); }
      return originalGet(args);
    };
    const signOut = client.signOut();
    await started;
    expect(await client.current()).toBeNull();
    release();
    await expect(signOut).rejects.toBeInstanceOf(OpenKeyNativeError);
    expect(f.revokeCalls).toBe(0);
    expect(f.plugin.values.size).toBe(1);
    f.plugin.secureStoreGet = originalGet;
    expect((await client.current())?.tokens.refreshToken).toBe('initial');
    expect((await client.renew()).tokens.refreshToken).toBe('next');
  });

  test('a failed signOut CAS read leaves a replacement session visible', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const replacement = fixture();
    replacement.setTokenReply(() => response(200, { access_token: 'access-b', refresh_token: 'second', tinycloud_delegation: replacement.delegation() }));
    await replacement.make().signIn({ capabilities });
    const [key, value] = sessionEntry(replacement.plugin);
    f.setRevokeReply(() => { f.plugin.values.set(key, value); return response(200, {}); });
    const originalGet = f.plugin.secureStoreGet.bind(f.plugin);
    let reads = 0;
    f.plugin.secureStoreGet = async (args) => {
      if (args.key === key && ++reads === 2) throw new Error('decrypt');
      return originalGet(args);
    };
    await expect(client.signOut()).rejects.toMatchObject({ code: 'NETWORK' });
    expect(f.revokeTokens).toEqual(['initial']);
    expect((await client.current())?.tokens.refreshToken).toBe('second');
  });

  test('a TinyCloud session save already in flight is followed by the signOut wipe', async () => {
    const f = fixture(); const client = f.make(); const session = await client.signIn({ capabilities });
    const originalSet = f.plugin.secureStoreSet.bind(f.plugin);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.plugin.secureStoreSet = async (item) => {
      if (item.key.includes(':tinycloud:')) { entered(); await gate; }
      await originalSet(item);
    };
    const save = client.sessionStorageAdapter().save(session.delegation.address!, persisted(session));
    await started;
    const signOut = client.signOut();
    release();
    await Promise.all([save, signOut]);
    expect(await client.sessionStorageAdapter().load(session.delegation.address!)).toBeNull();
    await client.signIn({ capabilities });
    expect(client.sessionStorageAdapter().exists(session.delegation.address!)).toBe(false);
  });

  test('a TinyCloud handoff after signOut cannot restore the old session', async () => {
    const f = fixture(); const client = f.make(); const old = await client.signIn({ capabilities });
    await client.signOut();
    await expect(client.sessionStorageAdapter().save(old.delegation.address!, persisted(old))).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(await client.sessionStorageAdapter().load(old.delegation.address!)).toBeNull();
    const fresh = await client.signIn({ capabilities });
    await expect(client.sessionStorageAdapter().save(old.delegation.address!, persisted(old))).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    await client.sessionStorageAdapter().save(fresh.delegation.address!, persisted(fresh));
    expect((await client.sessionStorageAdapter().load(fresh.delegation.address!))?.sessionKey).toBe(JSON.stringify(fresh.sessionKey.privateJwk));
  });

  test('signIn then signOut in the same tick always wipes', async () => {
    const f = fixture(); const client = f.make();
    await client.signIn({ capabilities });
    const signIn = client.signIn({ capabilities });
    const signOut = client.signOut();
    await signOut;
    await expect(signIn).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(await client.current()).toBeNull();
    expect(f.plugin.values.size).toBe(0);
  });

  test('a new sign-in waits for an existing renew before replacing the session', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.setRenewReply(() => ({ ...response(200, f.renewal('old')), json: async () => { entered(); await gate; return f.renewal('old'); } }));
    const old = client.renew(); await started;
    const freshPending = client.signIn({ capabilities });
    release();
    expect((await old).tokens.refreshToken).toBe('old');
    const fresh = await freshPending;
    expect((await client.current())?.sessionKey.did).toBe(fresh.sessionKey.did);
    expect((await client.current())?.tokens.refreshToken).toBe('initial');
  });

  test('a cancelled replacement sign-in does not invalidate an in-flight renew (P3)', async () => {
    const f = fixture(); const client = f.make(); const existing = await client.signIn({ capabilities });
    const oldRenewal = f.renewal('rotated');
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.setRenewReply(() => ({ ...response(200, oldRenewal), json: async () => { entered(); await gate; return oldRenewal; } }));
    const renewal = client.renew();
    await started;
    f.plugin.callback = async () => { throw { code: 'USER_CANCELLED' }; };
    await expect(client.signIn({ capabilities })).rejects.toMatchObject({ code: 'USER_CANCELLED' });
    release();
    expect((await renewal).tokens.refreshToken).toBe('rotated');
    expect((await client.current())?.sessionKey.did).toBe(existing.sessionKey.did);
    expect((await client.current())?.tokens.refreshToken).toBe('rotated');
    expect(f.revokeTokens).not.toContain('rotated');
  });

  test('transient revoke failure wipes and reports that the grant may remain active', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(client.signOut()).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE', message: 'Local state was cleared; the server grant may still be active' });
    expect(await client.current()).toBeNull();
    expect(f.revokeCalls).toBe(2);
  });

  test('transient signOut keeps only a pending revoke and retries on next signOut', async () => {
    const f = fixture(); const client = f.make(); const session = await client.signIn({ capabilities });
    const storage = client.sessionStorageAdapter();
    await storage.save(session.delegation.address!, persisted(session));
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(client.signOut()).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE' });
    expect(await client.current()).toBeNull();
    expect(await storage.load(session.delegation.address!)).toBeNull();
    expect(storage.exists(session.delegation.address!)).toBe(false);
    expect(storage.activeAddress()).toBeUndefined();
    const entries = [...f.plugin.values];
    expect(entries).toHaveLength(1);
    expect(entries[0]![0].endsWith(':pending-revoke')).toBe(true);
    const pending = JSON.parse(entries[0]![1]);
    expect(Object.keys(pending).sort()).toEqual(['grants', 'version']);
    expect(Object.keys(pending.grants[0]).sort()).toEqual(['attempts', 'expiresAt', 'privateJwk', 'refreshToken']);
    expect(pending.grants[0].refreshToken).toBe('initial');
    expect(pending.grants[0].attempts).toBe(1);
    expect(pending.grants[0].expiresAt).toBeGreaterThan(Date.now());
    f.setRevokeReply(() => response(200, {}));
    await client.signOut();
    expect(f.revokeCalls).toBe(3);
    expect(f.plugin.values.size).toBe(0);
  });

  test('signOut hides both stores before a slow transient revoke finishes', async () => {
    const f = fixture(); const client = f.make(); const session = await client.signIn({ capabilities });
    const storage = client.sessionStorageAdapter();
    await storage.save(session.delegation.address!, persisted(session));
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.setRevokeReply(async () => { entered(); await gate; return response(503, { error: 'temporarily_unavailable' }, '1'); });
    const signOut = client.signOut();
    await started;
    expect(await client.current()).toBeNull();
    expect(await storage.load(session.delegation.address!)).toBeNull();
    expect(storage.exists(session.delegation.address!)).toBe(false);
    release();
    await expect(signOut).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE' });
  });

  test('a terminal retry removes the pending revoke record', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(client.signOut()).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE' });
    f.setRevokeReply(() => response(401, { error: 'invalid_session_proof' }));
    await client.signOut();
    expect(f.plugin.values.size).toBe(0);
  });

  test('revoke classification keeps 429 and generic 5xx, but drops other 4xx', async () => {
    for (const status of [429, 500, 503, 400, 403]) {
      const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
      f.setRevokeReply(() => response(status, { error: 'unexpected_error' }));
      if (status === 429 || status >= 500) {
        await expect(client.signOut()).rejects.toMatchObject({ status });
        expect([...f.plugin.values.keys()].some((key) => key.endsWith(':pending-revoke'))).toBe(true);
      } else {
        await client.signOut();
        expect(f.plugin.values.size).toBe(0);
      }
    }
  });

  test('discovery 503 during signOut keeps a bounded pending revoke', async () => {
    const f = fixture(); await f.make().signIn({ capabilities });
    f.setDiscoveryReply(() => response(503, { error: 'offline' }));
    const fresh = f.make();
    await expect(fresh.signOut()).rejects.toMatchObject({ code: 'SERVER', status: 503 });
    const pending = JSON.parse([...f.plugin.values].find(([key]) => key.endsWith(':pending-revoke'))![1]);
    expect(pending.grants).toHaveLength(1);
    expect(pending.grants[0].attempts).toBe(1);
    expect(await fresh.current()).toBeNull();
  });

  test('pending revoke retries stop at 20 attempts or refresh expiry', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRevokeReply(() => response(500, { error: 'unexpected_error' }));
    await expect(client.signOut()).rejects.toMatchObject({ status: 500 });
    const key = [...f.plugin.values.keys()].find((item) => item.endsWith(':pending-revoke'))!;
    const record = JSON.parse(f.plugin.values.get(key)!);
    record.grants[0].attempts = 19;
    f.plugin.values.set(key, JSON.stringify(record));
    await expect(client.signOut()).rejects.toMatchObject({ status: 500 });
    expect(f.plugin.values.has(key)).toBe(false);
    const calls = f.revokeCalls;
    await client.signOut();
    expect(f.revokeCalls).toBe(calls);

    await client.signIn({ capabilities });
    await expect(client.signOut()).rejects.toMatchObject({ status: 500 });
    const expired = JSON.parse(f.plugin.values.get(key)!);
    expired.grants[0].expiresAt = Date.now() - 1;
    f.plugin.values.set(key, JSON.stringify(expired));
    const beforeExpiry = f.revokeCalls;
    await client.signOut();
    expect(f.revokeCalls).toBe(beforeExpiry);
    expect(f.plugin.values.has(key)).toBe(false);
  });

  test('pending revoke entries from the prior SDK revision gain retry bounds', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRevokeReply(() => response(500, { error: 'unexpected_error' }));
    await expect(client.signOut()).rejects.toMatchObject({ status: 500 });
    const key = [...f.plugin.values.keys()].find((item) => item.endsWith(':pending-revoke'))!;
    const legacy = JSON.parse(f.plugin.values.get(key)!);
    delete legacy.grants[0].attempts;
    delete legacy.grants[0].expiresAt;
    f.plugin.values.set(key, JSON.stringify(legacy));
    await expect(client.signOut()).rejects.toMatchObject({ status: 500 });
    const upgraded = JSON.parse(f.plugin.values.get(key)!);
    expect(upgraded.grants[0].attempts).toBe(2);
    expect(upgraded.grants[0].expiresAt).toBeGreaterThan(Date.now());
  });

  test('a corrupt pending revoke is deleted before the next signOut', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const key = sessionEntry(f.plugin)[0].replace(/:session$/, ':pending-revoke');
    f.plugin.values.set(key, '{broken');
    await client.signOut();
    expect(f.plugin.values.size).toBe(0);
    expect(f.revokeCalls).toBe(1);
  });

  test('pending expiry uses token issue time and caps at renewableUntil plus five minutes', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const [key, value] = sessionEntry(f.plugin);
    const record = JSON.parse(value);
    record.refreshIssuedAt = Date.now() - 8 * 24 * 60 * 60 * 1000;
    f.plugin.values.set(key, JSON.stringify(record));
    f.setRevokeReply(() => response(500, { error: 'unexpected_error' }));
    await expect(client.signOut()).rejects.toMatchObject({ status: 500 });
    expect(f.plugin.values.size).toBe(0);

    await client.signIn({ capabilities });
    const [newKey, newValue] = sessionEntry(f.plugin);
    const capped = JSON.parse(newValue);
    capped.delegation.renewableUntil = new Date(Date.now() + 60_000).toISOString();
    f.plugin.values.set(newKey, JSON.stringify(capped));
    await expect(client.signOut()).rejects.toMatchObject({ status: 500 });
    const pending = JSON.parse([...f.plugin.values].find(([item]) => item.endsWith(':pending-revoke'))![1]);
    expect(pending.grants[0].expiresAt).toBeGreaterThan(Date.now() + 350_000);
    expect(pending.grants[0].expiresAt).toBeLessThan(Date.now() + 370_000);
  });

  test('a rotated refresh token gets a new issue time for pending-revoke expiry', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const [key, value] = sessionEntry(f.plugin);
    const old = JSON.parse(value);
    old.refreshIssuedAt = Date.now() - 8 * 24 * 60 * 60 * 1000;
    f.plugin.values.set(key, JSON.stringify(old));
    f.setRenewReply(() => response(200, f.renewal('rotated')));
    await client.renew();
    const rotated = JSON.parse(sessionEntry(f.plugin)[1]);
    expect(rotated.refreshIssuedAt).toBeGreaterThan(Date.now() - 5_000);
    f.setRevokeReply(() => response(500, { error: 'unexpected_error' }));
    await expect(client.signOut()).rejects.toMatchObject({ status: 500 });
    const pending = JSON.parse([...f.plugin.values].find(([item]) => item.endsWith(':pending-revoke'))![1]);
    expect(pending.grants[0].refreshToken).toBe('rotated');
    expect(pending.grants[0].expiresAt).toBeGreaterThan(Date.now() + 6 * 24 * 60 * 60 * 1000);
  });

  test('an already expired grant is not kept for pending revoke', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    for (const [key, value] of f.plugin.values) {
      if (key.endsWith(':session')) {
        const record = JSON.parse(value);
        record.delegation.renewableUntil = new Date(Date.now() - 301_000).toISOString();
        f.plugin.values.set(key, JSON.stringify(record));
      }
    }
    f.setRevokeReply(() => response(500, { error: 'unexpected_error' }));
    await expect(client.signOut()).rejects.toMatchObject({ status: 500 });
    expect(f.plugin.values.size).toBe(0);
  });

  test('offline pending revoke retries discovery after recovery and permits signIn, renew, signOut', async () => {
    const f = fixture(); const initial = f.make(); await initial.signIn({ capabilities });
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(initial.signOut()).rejects.toMatchObject({ status: 503 });
    f.setDiscoveryReply(() => response(503, { error: 'offline' }));
    const recovered = f.make();
    const discoveryCount = () => f.requestLog.filter((url) => url.includes('.well-known')).length;
    const offlineCount = discoveryCount();
    await eventually(() => discoveryCount() > offlineCount);
    expect([...f.plugin.values.keys()].some((key) => key.endsWith(':pending-revoke'))).toBe(true);
    f.setDiscoveryReply(() => response(200, {
      issuer, authorization_endpoint: `${issuer}/oauth2/authorize`, token_endpoint: `${issuer}/oauth2/token`,
      pushed_authorization_request_endpoint: `${issuer}/oauth2/par`,
      tinycloud_delegation_renew_endpoint: `${issuer}/oauth2/tinycloud/renew`,
      tinycloud_delegation_revocation_endpoint: `${issuer}/oauth2/tinycloud/revoke`,
    }));
    f.setRevokeReply(() => response(200, {}));
    expect((await recovered.signIn({ capabilities })).tokens.refreshToken).toBe('initial');
    expect((await recovered.renew()).tokens.refreshToken).toBe('next');
    await recovered.signOut();
    expect(await recovered.current()).toBeNull();
    expect(f.plugin.values.size).toBe(0);
    expect(discoveryCount()).toBeGreaterThan(offlineCount + 1);
  });

  test('pending revoke retries at SDK initialization and before signIn', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(client.signOut()).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE' });
    const pendingKey = [...f.plugin.values.keys()].find((key) => key.endsWith(':pending-revoke'))!;
    f.setRevokeReply(() => response(200, {}));
    f.make(); // constructor starts a background retry
    await eventually(() => !f.plugin.values.has(pendingKey));
    expect(f.revokeCalls).toBe(3);

    await client.signIn({ capabilities });
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(client.signOut()).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE' });
    f.setRevokeReply(() => response(200, {}));
    const start = f.requestLog.length;
    await client.signIn({ capabilities });
    const calls = f.requestLog.slice(start);
    expect(calls.findIndex((url) => url.endsWith('/revoke'))).toBeLessThan(calls.findIndex((url) => url.endsWith('/par')));
    expect(f.plugin.values.has(pendingKey)).toBe(false);
  });

  test('cancel, access_denied and state mismatch on a new signIn preserve the old session', async () => {
    const f = fixture(); const client = f.make(); const existing = await client.signIn({ capabilities });
    await client.sessionStorageAdapter().save(existing.delegation.address!, persisted(existing));
    for (const code of ['USER_CANCELLED', 'ACCESS_DENIED', 'STATE_MISMATCH'] as const) {
      f.plugin.callback = code === 'USER_CANCELLED'
        ? async () => { throw { code: 'USER_CANCELLED' }; }
        : code === 'ACCESS_DENIED'
          ? async () => `${redirectUri}?error=access_denied&state=${f.state}&iss=${encodeURIComponent(issuer)}`
          : async () => `${redirectUri}?code=x&state=wrong&iss=${encodeURIComponent(issuer)}`;
      await expect(client.signIn({ capabilities })).rejects.toMatchObject({ code });
      expect((await client.current())?.tokens.refreshToken).toBe('initial');
      expect((await client.sessionStorageAdapter().load(existing.delegation.address!))?.sessionKey)
        .toBe(JSON.stringify(existing.sessionKey.privateJwk));
    }
  });

  test('a secure-store read failure does not remove or revoke the session', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.plugin.failGet = true;
    await expect(client.signOut()).rejects.toMatchObject({ code: 'NETWORK', message: 'OpenKey secure-store read failed: decrypt' });
    expect(f.revokeCalls).toBe(0);
    expect(f.plugin.values.size).toBe(1);
    f.plugin.failGet = false;
    expect((await client.current())?.tokens.refreshToken).toBe('initial');
    expect((await client.renew()).tokens.refreshToken).toBe('next');
  });

  test('a readable but corrupt session can be removed on signOut', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    const [key] = sessionEntry(f.plugin);
    f.plugin.values.set(key, '{broken');
    await expect(client.signOut()).rejects.toMatchObject({ code: 'SERVER', message: 'Stored OpenKey session is invalid' });
    expect(f.plugin.values.size).toBe(0);
    expect(f.revokeCalls).toBe(0);
  });

  test('signOut reports a local wipe failure', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.plugin.failRemove = true;
    await expect(client.signOut()).rejects.toMatchObject({ code: 'SERVER', message: 'Local secure-store wipe failed' });
  });

  test('immediate renew failure rejects signIn and removes the initial session', async () => {
    const f = fixture(); f.setImmediateRenewal();
    f.setRenewReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    const client = f.make();
    await expect(client.signIn({ capabilities })).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE' });
    expect(f.renewCalls).toBe(2);
    expect(await client.current()).toBeNull();
  });

  test('successful cleanup removes rotatedRefreshToken from an exchange error', async () => {
    const f = fixture();
    f.setTokenReply(() => response(200, { access_token: 'access', refresh_token: 'live', tinycloud_delegation: { ...f.delegation(), verificationMethod: 'wrong' } }));
    try { await f.make().signIn({ capabilities }); throw new Error('expected failure'); }
    catch (error) {
      expect(error).toMatchObject({ code: 'SERVER' });
      expect((error as OpenKeyNativeError).rotatedRefreshToken).toBeUndefined();
    }
    expect(f.revokeCalls).toBe(1);
  });

  test('failed cleanup retains the live token on an exchange error', async () => {
    const f = fixture();
    f.setTokenReply(() => response(200, { access_token: 'access', refresh_token: 'live', tinycloud_delegation: { ...f.delegation(), verificationMethod: 'wrong' } }));
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(f.make().signIn({ capabilities })).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'live' });
    const pending = JSON.parse([...f.plugin.values].find(([key]) => key.endsWith(':pending-revoke'))![1]);
    expect(pending.grants.map((grant: { refreshToken: string }) => grant.refreshToken)).toEqual(['live']);
  });

  test('seeded sign-in, renew, sign-out and pending-revoke interleavings account for live grants', async () => {
    const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
    for (let seed = 1; seed <= 30; seed++) {
      let state = seed;
      const random = () => {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        return state / 0x100000000;
      };
      const f = fixture(); const client = f.make();
      const live = new Set<string>();
      let serial = 0;
      f.setTokenReply(() => {
        const token = `grant-${seed}-${++serial}`;
        live.add(token);
        return response(200, { access_token: 'access', refresh_token: token, tinycloud_delegation: f.delegation() });
      });
      f.setRenewReply(() => {
        const old = f.renewTokens.at(-1)!;
        if (!live.has(old)) return response(400, { error: 'invalid_grant' });
        live.delete(old);
        const token = `grant-${seed}-${++serial}`;
        live.add(token);
        return response(200, f.renewal(token));
      });
      await client.signIn({ capabilities });
      f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
      await client.signOut().catch(() => {});
      f.setRevokeReply(() => {
        if (random() < 0.35) return response(503, { error: 'temporarily_unavailable' }, '1');
        live.delete(f.revokeTokens.at(-1)!);
        return response(200, {});
      });
      await client.signIn({ capabilities });
      const order: ('renew' | 'signIn' | 'signOut')[] = ['renew', 'signIn', 'signOut'];
      for (let i = order.length - 1; i > 0; i--) {
        const j = Math.floor(random() * (i + 1));
        [order[i], order[j]] = [order[j], order[i]];
      }
      const operations: Promise<unknown>[] = [];
      for (const operation of order) {
        const pending = operation === 'renew' ? client.renew() : operation === 'signIn'
          ? client.signIn({ capabilities }) : client.signOut();
        operations.push(pending.catch(() => {}));
        await tick();
      }
      await Promise.allSettled(operations);
      const stored = [...f.plugin.values].find(([key]) => key.endsWith(':session'));
      const storedToken = stored ? (JSON.parse(stored[1]) as { tokens: { refreshToken: string } }).tokens.refreshToken : null;
      const pending = [...f.plugin.values].find(([key]) => key.endsWith(':pending-revoke'));
      const pendingTokens = pending ? (JSON.parse(pending[1]) as { grants: { refreshToken: string }[] }).grants.map((grant) => grant.refreshToken) : [];
      for (const token of live) {
        expect(storedToken === token || pendingTokens.includes(token)).toBe(true);
      }
      if (order.at(-1) === 'signOut') expect(storedToken).toBeNull();
    }
  });
});
