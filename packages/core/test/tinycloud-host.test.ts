import { expect, test } from 'bun:test';
import { sameTinyCloudHost } from '../src/tinycloud-host';

const node = 'https://node.tinycloud.xyz';
const tee = 'https://tee.node.tinycloud.xyz';
test('production node aliases match in both directions', () => {
  expect(sameTinyCloudHost(node, tee)).toBe(true);
  expect(sameTinyCloudHost(tee, node)).toBe(true);
});
test('other hosts require exact equality and cannot impersonate production', () => {
  for (const other of ['https://evil.example', 'https://node.tinycloud.xyz.evil.example', 'https://tee-node.tinycloud.xyz', 'http://node.tinycloud.xyz', 'https://node.tinycloud.xyz:444', node + '/', node + '/path', 'https://user@node.tinycloud.xyz']) {
    expect(sameTinyCloudHost(other, node)).toBe(false);
    expect(sameTinyCloudHost(tee, other)).toBe(false);
    expect(sameTinyCloudHost(other, other)).toBe(true);
  }
});

import { generateSessionKeypair, validateTinyCloudDelegation } from '../src/native-delegation';
test('native validation accepts production aliases in either direction without changing the grant', () => {
  const key = generateSessionKeypair();
  for (const [host, expected] of [[node, tee], [tee, node]]) {
    const grant = {
      version: 1, grantId: 'alias-grant', address: '0xabc', chainId: 1,
      ownerDid: 'did:pkh:eip155:1:0xabc', spaceId: 'tinycloud:pkh:eip155:1:0xabc:applications',
      verificationMethod: key.keyId, siwe: 'siwe', signature: '0xsig',
      delegationHeader: { Authorization: 'ucan' }, delegationCid: 'bafy',
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 3600000).toISOString(),
      renewableUntil: new Date(Date.now() + 86400000).toISOString(), permissions: [], tinycloudHost: host, hosting: 'existing',
    };
    const options = { sessionKey: key, requestedPermissions: [], expectedTinycloudHost: expected! };
    expect(validateTinyCloudDelegation(grant, options).tinycloudHost).toBe(host);
    for (const other of ['https://evil.example', 'https://node.tinycloud.xyz.evil.example', 'https://tee-node.tinycloud.xyz', 'https://node.tinycloud.xyz:444']) {
      expect(() => validateTinyCloudDelegation({ ...grant, tinycloudHost: other }, options)).toThrow();
    }
  }
});
