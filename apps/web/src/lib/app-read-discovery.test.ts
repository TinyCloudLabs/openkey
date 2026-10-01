// @ts-expect-error bun:test is a runtime-only module; tsc does not ship its types
import { describe, expect, test } from 'bun:test';
import { discoverApplicationReads, selectApplicationRead } from './app-read-discovery';

const ownerDid = 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111';
const account = `tinycloud:${ownerDid.slice(4)}:account`;
const appSpace = `tinycloud:${ownerDid.slice(4)}:health`;
const request = { keyId: 'key-1', keyType: 'MANAGED', jwk: { kty: 'OKP', crv: 'Ed25519', x: 'key' }, host: 'https://node.tinycloud.xyz', reason: 'When was my last weight-in?' };
const fixture = () => ({
  schemaVersion: 1, discoveryToken: 'private-discovery-context', ownerDid, host: request.host,
  clientKeyDigest: 'client-key-digest', expiresAt: '2099-01-01T00:00:00Z', complete: true, issues: [],
  applications: [{ appId: 'health', name: 'Health records', description: 'Weight and sleep', manifests: [], manifestHash: 'manifest-hash', selectionDigest: 'selection-digest', permissions: [
    { service: 'tinycloud.kv', space: account, path: 'applications/', actions: ['get', 'list'] },
    { service: 'tinycloud.capabilities', space: account, path: '', actions: ['read'] },
    { service: 'tinycloud.kv', space: appSpace, path: 'private/knowledge/', actions: ['get'] },
    { service: 'tinycloud.sql', space: appSpace, path: 'fitness', actions: ['read'] },
    { service: 'tinycloud.capabilities', space: appSpace, path: '', actions: ['read'] },
  ] }],
});

describe('application selection within one approval', () => {
  test('discovers using the selected managed account without requesting a delegation', async () => {
    const calls: Array<{ url: string; body: any; credentials?: RequestCredentials }> = [];
    const result = await discoverApplicationReads(request, async (url, init) => {
      calls.push({ url: String(url), body: JSON.parse(String(init?.body)), credentials: init?.credentials });
      return Response.json(fixture());
    });
    expect(calls).toEqual([{ url: '/api/delegate/app-read-discovery', body: { keyId: request.keyId, jwk: request.jwk, host: request.host, reason: request.reason }, credentials: 'include' }]);
    expect(result.applications[0].permissions).toEqual(fixture().applications[0].permissions);
  });

  test('binds the selected app to its server discovery context without regenerating permissions', async () => {
    const result = await discoverApplicationReads(request, async () => Response.json(fixture()));
    expect(selectApplicationRead(result, 'health')).toEqual({ discoveryToken: result.discoveryToken, appId: 'health', selectionDigest: 'selection-digest' });
    expect(() => selectApplicationRead(result, 'unlisted')).toThrow('Choose an application from this sign-in');
  });

  test('blocks external account discovery before any network or signature request', async () => {
    let calls = 0;
    await expect(discoverApplicationReads({ ...request, keyType: 'EXTERNAL' }, async () => { calls++; return Response.json(fixture()); })).rejects.toMatchObject({ code: 'app_read_managed_key_required' });
    expect(calls).toBe(0);
  });

  test('accepts qualified read verbs only for their declared service', async () => {
    const value = fixture();
    for (const permission of value.applications[0].permissions) permission.actions = permission.actions.map(action => `${permission.service}/${action}`);
    value.applications[0].permissions[2].actions.push('tinycloud.kv/metadata');
    const result = await discoverApplicationReads(request, async () => Response.json(value));
    expect(result.applications[0].permissions).toEqual(value.applications[0].permissions);
    value.applications[0].permissions[3].actions = ['tinycloud.kv/get'];
    await expect(discoverApplicationReads(request, async () => Response.json(value))).rejects.toMatchObject({ code: 'app_read_discovery_invalid' });
  });

  test('rejects write, unknown and cross-owner scopes instead of displaying them as read access', async () => {
    for (const change of [
      { service: 'tinycloud.kv', actions: ['put'] },
      { service: 'tinycloud.sql', actions: ['admin'] },
      { service: 'tinycloud.secret', actions: ['read'] },
      { space: 'tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:health' },
    ]) {
      const value = fixture();
      Object.assign(value.applications[0].permissions[2], change);
      await expect(discoverApplicationReads(request, async () => Response.json(value))).rejects.toMatchObject({ code: 'app_read_discovery_invalid' });
    }
  });

  test('rejects invalid, expired and wrong-host discovery without falling back to default access', async () => {
    for (const change of [{ complete: 'unknown' }, { expiresAt: '2000-01-01T00:00:00Z' }, { host: 'https://other.example' }, { discoveryToken: '' }]) {
      await expect(discoverApplicationReads(request, async () => Response.json({ ...fixture(), ...change }))).rejects.toMatchObject({ code: 'app_read_discovery_invalid' });
    }
  });

  test('preserves partial discovery and issues while allowing a validated app selection', async () => {
    const result = await discoverApplicationReads(request, async () => Response.json({ ...fixture(), complete: false, issues: [{ key: 'applications/old', code: 'LEGACY', category: 'invalid_record', field: 'manifests' }] }));
    expect(result.complete).toBe(false);
    expect(result.issues).toHaveLength(1);
    expect(selectApplicationRead(result, 'health').appId).toBe('health');
  });

  test('keeps unavailable registry failures distinct from an empty application list', async () => {
    await expect(discoverApplicationReads(request, async () => Response.json({ error: 'private upstream detail', code: 'app_read_registry_unavailable' }, { status: 503 }))).rejects.toMatchObject({ code: 'app_read_registry_unavailable' });
    const empty = await discoverApplicationReads(request, async () => Response.json({ ...fixture(), applications: [] }));
    expect(empty.applications).toEqual([]);
  });
});
