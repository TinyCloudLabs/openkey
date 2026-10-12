import { describe, expect, test } from 'bun:test';
import { canonicalTrustedTinyCloudHost, TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS } from '../services/tinycloud-hosts';

const NODE = 'https://node.tinycloud.xyz';
const TEE = 'https://tee.node.tinycloud.xyz';

describe('canonicalTrustedTinyCloudHost (TC-943)', () => {
  test('pins the allowlist to exactly the two node names', () => {
    expect([...TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS].sort()).toEqual([NODE, TEE]);
  });

  for (const configured of [NODE, TEE]) {
    for (const raw of [NODE, TEE, `${NODE}/`, `${TEE}/`, 'HTTPS://TEE.NODE.TINYCLOUD.XYZ', 'https://Node.TinyCloud.xyz/']) {
      test(`maps alias ${raw} to configured host ${configured}`, () => {
        expect(canonicalTrustedTinyCloudHost(raw, configured)).toBe(configured);
      });
    }
  }

  const rejected: unknown[] = [
    'https://evil.node.tinycloud.xyz',
    'https://node.tinycloud.xyz.evil.com',
    'https://tee.node.tinycloud.xyz.',
    'https://node.tinycloud.xyz.',
    'http://node.tinycloud.xyz',
    'http://tee.node.tinycloud.xyz',
    'wss://node.tinycloud.xyz',
    'https://node.tinycloud.xyz:443',
    'https://node.tinycloud.xyz:8443',
    'https://user@node.tinycloud.xyz',
    'https://user:pw@tee.node.tinycloud.xyz',
    'https://node.tinycloud.xyz/path',
    'https://node.tinycloud.xyz//',
    'https://node.tinycloud.xyz?x=1',
    'https://node.tinycloud.xyz#f',
    'https:node.tinycloud.xyz',
    'https:\\\\node.tinycloud.xyz',
    ' https://node.tinycloud.xyz',
    'https://node.tinycloud.xyz\t',
    'https://node.tinycloud.xyz\n',
    'https://nöde.tinycloud.xyz',
    'https://node.tinyclοud.xyz',
    'https://xn--nde-sna.tinycloud.xyz',
    'https://node.tinуcloud.xyz',
    'https://node.tinyclouK.xyz',
    '',
    'not a url',
    'node.tinycloud.xyz',
    null,
    undefined,
    42,
    {},
  ];
  for (const raw of rejected) {
    test(`rejects look-alikes and non-origin forms: ${JSON.stringify(raw)}`, () => {
      expect(canonicalTrustedTinyCloudHost(raw, NODE)).toBeNull();
    });
  }

  test('does not widen a local-dev configured host', () => {
    const local = 'http://127.0.0.1:49152';
    expect(canonicalTrustedTinyCloudHost(local, local)).toBe(local);
    for (const raw of [NODE, TEE, `${local}/`, 'http://localhost:49152']) {
      expect(canonicalTrustedTinyCloudHost(raw, local)).toBeNull();
    }
  });

  test('never returns the raw input', () => {
    expect(canonicalTrustedTinyCloudHost('HTTPS://TEE.NODE.TINYCLOUD.XYZ/', NODE)).toBe(NODE);
  });
});
