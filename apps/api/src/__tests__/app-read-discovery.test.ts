import { expect, test } from 'bun:test';
const service = await import('../services/app-read-discovery').catch(() => ({} as any));
const ownerAddress = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const request = { userId: 'user-1', keyId: 'key-1', host: 'https://node.tinycloud.xyz', jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, reason: 'Read my latest weight' };
const record = { app_id: 'fitness', manifests: [{ app_id: 'fitness', name: 'Fitness', space: 'applications', defaults: false, includePublicSpace: false, permissions: [{ service: 'tinycloud.sql', path: 'fitness', skipPrefix: true, actions: ['read', 'write'] }] }] };
function fixture() {
  expect(typeof service.createAppReadDiscovery).toBe('function');
  const accesses: unknown[] = [];
  let time = 100000;
  const dependencies = { getKey: async (userId: string, keyId: string) => { accesses.push({ userId, keyId }); return userId === 'user-1' && keyId === 'key-1' ? { id: keyId, userId, address: ownerAddress, keyType: 'MANAGED', sealedBlob: 'opaque-test' } : null; },
    signMessage: async () => 'synthetic-unused',
    readRegistry: async () => ({ records: [{ key: 'applications/fitness', value: record }], truncated: false }), now: () => time,
  };
  return { dependencies, accesses, create: () => service.createAppReadDiscovery(dependencies), expire: () => { time += 11 * 60000; } };
}
test('discovery decodes canonical records, projects only read scope and binds selection to native requester', async () => {
  const f = fixture(), discovery = f.create();
  const result = await discovery.discover(request);
  expect(result.applications).toHaveLength(1);
  expect(result.applications[0].manifestHash).toMatch(/^[a-f0-9]{16}$/);
  expect(result.applications[0].permissions.some((p: any) => p.actions.some((a: string) => /write|put|schema/.test(a)))).toBe(false);
  const selection = discovery.select({ ...request, discoveryToken: result.discoveryToken, appId: 'fitness', selectionDigest: result.applications[0].selectionDigest });
  expect(selection.permissions).toEqual(result.applications[0].permissions);
  expect(selection.appReadSelection.permissions).toEqual(selection.permissions);
  for (const changed of [{ userId: 'other' }, { keyId: 'other' }, { host: 'https://tee.node.tinycloud.xyz' }, { jwk: { ...request.jwk, x: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' } }, { appId: 'other' }, { selectionDigest: '0'.repeat(64) }, { permissions: [{ service: 'tinycloud.sql', space: 'applications', path: 'fitness', actions: ['tinycloud.sql/write'] }] }]) {
    expect(() => discovery.select({ ...request, discoveryToken: result.discoveryToken, appId: 'fitness', selectionDigest: result.applications[0].selectionDigest, ...changed })).toThrow();
  }
  f.expire();
  expect(() => discovery.select({ ...request, discoveryToken: result.discoveryToken, appId: 'fitness', selectionDigest: result.applications[0].selectionDigest })).toThrow('app_read_discovery_expired');
});
test('valid canonical apps remain selectable when unrelated registry records are legacy', async () => {
  const f = fixture();
  f.dependencies.readRegistry = async () => ({ records: [
    { key: 'applications/fitness', value: record },
    { key: 'applications/legacy', value: { manifest: record.manifests[0] } as any },
  ], truncated: false });
  const discovery = f.create();
  const result = await discovery.discover(request);
  expect(result.complete).toBe(false);
  expect(result.issues).toHaveLength(1);
  expect(result.issues[0].code).toBe('LEGACY_APPLICATION_RECORD');
  expect(result.applications).toHaveLength(1);
  expect(discovery.select({ ...request, discoveryToken: result.discoveryToken, appId: 'fitness', selectionDigest: result.applications[0].selectionDigest }).permissions).toEqual(result.applications[0].permissions);
});
test('discovery reports legacy records and rejects missing ownership, external wallets and untrusted hosts before reads', async () => {
  const f = fixture();
  let reads = 0;
  f.dependencies.readRegistry = async () => { reads++; return { records: [{ key: 'applications/fitness', value: { manifest: record.manifests[0] } as any }], truncated: true }; };
  const discovery = f.create();
  const result = await discovery.discover(request);
  expect(result.applications).toHaveLength(0);
  expect(result.complete).toBe(false);
  expect(result.issues.some((i: any) => i.code === 'LEGACY_APPLICATION_RECORD')).toBe(true);
  for (const changed of [{ userId: 'other' }, { host: 'https://attacker.example' }, { host: 'https://node.tinycloud.xyz@attacker.example' }, { host: 'https://node.tinycloud.xyz/private' }]) await expect(discovery.discover({ ...request, ...changed })).rejects.toThrow();
  expect(reads).toBe(1);
  const external = service.createAppReadDiscovery({ ...f.dependencies, getKey: async () => ({ id: 'key-1', userId: 'user-1', address: ownerAddress, keyType: 'EXTERNAL' }) });
  await expect(external.discover(request)).rejects.toThrow('app_read_managed_key_required');
});
