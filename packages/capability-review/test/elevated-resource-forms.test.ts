import { expect, test } from 'bun:test';
import { isExactShareKeyGrant } from '../src/elevated.js';

const address = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const space = `tinycloud:pkh:eip155:1:${address}:default`;

test('the share-key review recognises text and parsed encryption resources', () => {
  for (const path of [
    `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default/share/TestKey`,
    `${space}/ENCRYPTION/SHARE/TestKey`,
    `${space}/tinycloud.encryption/Share/TestKey`,
    'share/TestKey',
  ]) {
    for (const verb of ['decrypt', 'key.create']) {
      expect(isExactShareKeyGrant({ service: 'tinycloud.encryption', space, path }, `tinycloud.encryption/${verb}`)).toBe(true);
    }
  }
  for (const service of ['kv', 'sql']) {
    expect(isExactShareKeyGrant({ service, space, path: 'share/TestKey' }, 'tinycloud.encryption/decrypt')).toBe(false);
  }
});
