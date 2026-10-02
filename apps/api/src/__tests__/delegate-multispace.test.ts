import { expect, test } from 'bun:test';
import { parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { prepareDelegationSession } from '../routes/delegate-session';
const address = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const account = `tinycloud:pkh:eip155:1:${address}:account`;
const applications = `tinycloud:pkh:eip155:1:${address}:applications`;
const base = { address, chainId: 1, prefix: 'account', jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, expiryMs: 3600000 };
const permissions = [
  { service: 'tinycloud.capabilities', space: account, path: '', actions: ['tinycloud.capabilities/read'] },
  { service: 'tinycloud.kv', space: account, path: 'applications/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
  { service: 'tinycloud.capabilities', space: applications, path: '', actions: ['tinycloud.capabilities/read'] },
  { service: 'tinycloud.sql', space: applications, path: 'measurements', actions: ['tinycloud.sql/read'] },
];
test('one proof contains the exact per-space union without a capability cross-product', () => {
  const result = prepareDelegationSession({ ...base, permissions });
  const recap = parseRecapFromSiwe(result.prepared.siwe);
  expect(recap).toHaveLength(4);
  expect(recap.some((entry: any) => entry.space === account && entry.service === 'sql')).toBe(false);
  expect(recap.some((entry: any) => entry.space === applications && entry.path === 'applications/')).toBe(false);
});
test('multi-space narrowing retains resources in their original space', () => {
  const initial = prepareDelegationSession({ ...base, permissions });
  const keys = initial.selectedActionKeys.filter(key => !key.endsWith('tinycloud.kv/get'));
  const result = prepareDelegationSession({ ...base, permissions, actionKeys: keys });
  expect(result.edited).toBe(true);
  const recap = parseRecapFromSiwe(result.prepared.siwe);
  expect(recap.find((entry: any) => entry.service === 'kv')?.actions).toEqual(['tinycloud.kv/list']);
  expect(recap.find((entry: any) => entry.service === 'sql')?.space).toBe(applications);
});
test('requested permissions cannot name another owner or chain', () => {
  for (const space of [account.replace(address, '0x1111111111111111111111111111111111111111'), account.replace(':eip155:1:', ':eip155:2:')]) {
    expect(() => prepareDelegationSession({ ...base, permissions: [{ ...permissions[0]!, space }] })).toThrow('signing identity');
  }
});
test('device-compatible dotted space names retain their exact owner and name', () => {
  for (const requested of ['notes.v1', `tinycloud:pkh:eip155:1:${address.toLowerCase()}:notes.v1`]) {
    const result = prepareDelegationSession({ ...base, permissions: permissions.slice(0, 2).map(entry => ({ ...entry, space: requested })) });
    expect(parseRecapFromSiwe(result.prepared.siwe).every((entry: any) => entry.space === `tinycloud:pkh:eip155:1:${address}:notes.v1`)).toBe(true);
  }
});
