import { expect, test } from 'bun:test';
import { sameTinyCloudHost as apiMatch } from '../services/tinycloud-hosts';
import { sameTinyCloudHost as sdkMatch } from '../../../../packages/core/src/tinycloud-host';

test('API and SDK use the same exact production alias rule', () => {
  const hosts = ['https://node.tinycloud.xyz', 'https://tee.node.tinycloud.xyz', 'https://evil.example', 'https://node.tinycloud.xyz.evil.example', 'https://tee-node.tinycloud.xyz', 'http://node.tinycloud.xyz', 'https://node.tinycloud.xyz:444', 'https://node.tinycloud.xyz/'];
  for (const a of hosts) for (const b of hosts) {
    expect(apiMatch(a, b)).toBe(sdkMatch(a, b));
    expect(apiMatch(a, b)).toBe(a === b || (hosts.slice(0, 2).includes(a) && hosts.slice(0, 2).includes(b)));
  }
});
