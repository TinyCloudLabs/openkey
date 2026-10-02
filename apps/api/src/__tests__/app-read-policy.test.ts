import { expect, test } from 'bun:test';
const policy = await import('../services/app-read-policy').catch(() => ({} as any));
const ownerDid = 'did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const app = { appId: 'my-fitness', manifestHash: 'verified-canonical-hash', manifests: [{ app_id: 'my-fitness', name: 'Fitness', space: 'applications', defaults: false, includePublicSpace: false, permissions: [
  { service: 'tinycloud.sql', path: 'measurements', skipPrefix: true, actions: ['read', 'write', 'schema'] },
  { service: 'tinycloud.kv', path: 'my-fitness/', skipPrefix: true, actions: ['get', 'list', 'put'] },
] }] };
test('derive exact account plus selected app read-only scope', () => {
  expect(typeof policy.deriveAppReadPermissions).toBe('function');
  const result = policy.deriveAppReadPermissions(app, { ownerDid });
  expect(result).toHaveLength(5);
  expect(result.flatMap((p: any) => p.actions).every((a: string) => !/write|put|schema|del|host/.test(a))).toBe(true);
  expect(result.some((p: any) => p.path === 'measurements' && p.space.endsWith(':applications') && p.actions[0] === 'tinycloud.sql/read')).toBe(true);
  expect(result.some((p: any) => p.path === 'applications/' && p.space.endsWith(':account'))).toBe(true);
});
test('does not invent broad defaults and rejects foreign owners and wildcard data grants', () => {
  expect(typeof policy.deriveAppReadPermissions).toBe('function');
  for (const changed of [{ path: '' }, { path: '*' }, { space: 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:applications' }]) {
    const bad = structuredClone(app); Object.assign(bad.manifests[0]!.permissions[0]!, changed);
    expect(() => policy.deriveAppReadPermissions(bad, { ownerDid })).toThrow();
  }
  const defaults = structuredClone(app); defaults.manifests[0]!.defaults = true;
  expect(policy.deriveAppReadPermissions(defaults, { ownerDid })).toEqual(policy.deriveAppReadPermissions(app, { ownerDid }));
});
test('selection binding changes for owner, host, public client key, app, manifest or scope changes', () => {
  expect(typeof policy.appReadSelection).toBe('function');
  const bound = { ownerDid, host: 'https://node.tinycloud.xyz', jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } };
  const first = policy.appReadSelection(app, bound);
  expect(first.protocolVersion).toBe(1);
  expect(first.selectionDigest).toMatch(/^[a-f0-9]{64}$/);
  for (const changed of [{ host: 'https://tee.node.tinycloud.xyz' }, { jwk: { ...bound.jwk, x: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' } }]) expect(policy.appReadSelection(app, { ...bound, ...changed }).selectionDigest).not.toBe(first.selectionDigest);
  expect(policy.appReadSelection({ ...app, manifestHash: 'changed' }, bound).selectionDigest).not.toBe(first.selectionDigest);
});
test('raw manifest constraints and expiry cannot be dropped by the installed resolver', () => {
  for (const field of ['caveats', 'constraints', 'conditions', 'expiry', 'expiresAt', 'expirationTime', 'notBefore']) {
    const constrained = structuredClone(app);
    Object.assign(constrained.manifests[0]!.permissions[0]!, { [field]: field === 'expiry' ? 300 : { restriction: 'must remain enforced' } });
    expect(() => policy.deriveAppReadPermissions(constrained, { ownerDid })).toThrow('app_read_scope_unsupported');
  }
});
test('does not offer canonical app IDs that the CLI cannot accept', () => {
  for (const appId of ['fitness:personal', 'a'.repeat(129), '_fitness']) {
    const incompatible = { ...app, appId, manifests: app.manifests.map(manifest => ({ ...manifest, app_id: appId })) };
    expect(() => policy.deriveAppReadPermissions(incompatible, { ownerDid })).toThrow('app_read_scope_unsupported');
  }
});
