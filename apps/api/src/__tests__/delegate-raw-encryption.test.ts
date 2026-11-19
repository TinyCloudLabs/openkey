import { describe, expect, test } from 'bun:test';
import { DelegateRequestError } from '../routes/delegate-validation';
import {
  parsePreparedRecap,
  prepareDelegationSession,
  type DelegationPermissionEntry,
} from '../routes/delegate-session';

// TC-598: a CLI `/delegate` request for a secret carries a raw encryption
// decrypt grant (`urn:tinycloud:encryption:<ownerDid>:<name>`). The node
// authorizes only the top-level network resource, so OpenKey must sign it as
// a raw ReCap resource, not nested under the session space.
//
// Set PRINT_SIWE=1 to print the prepared SIWE of the main case.

const address = '0xA8763f2b67aa9C807d2277a698cb071e3D86204A';
const chainId = 1;
const ownerDid = `did:pkh:eip155:${chainId}:${address}`;
const network = `urn:tinycloud:encryption:${ownerDid}:default`;
const space = `tinycloud:pkh:eip155:${chainId}:${address}:secrets`;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const expiryMs = 60 * 60 * 1000;
const DECRYPT = 'tinycloud.encryption/decrypt';

function secretRequest(raw: Partial<DelegationPermissionEntry> = {}): DelegationPermissionEntry[] {
  return [
    { service: 'tinycloud.kv', space, path: 'vault/secrets/TC_FWD_TOKEN', actions: ['tinycloud.kv/get'] },
    { service: 'tinycloud.encryption', space: 'encryption', path: network, actions: [DECRYPT], ...raw },
    { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] },
  ];
}

function prepare(permissions: DelegationPermissionEntry[], actionKeys?: string[]) {
  return prepareDelegationSession({ address, chainId, prefix: 'default', jwk, permissions, actionKeys, expiryMs });
}

/** The signed ReCap `att` map, decoded from the SIWE's `urn:recap:` resource. */
function recapAtt(siwe: string): Record<string, Record<string, unknown[]>> {
  const encoded = /^- urn:recap:(.+)$/m.exec(siwe)?.[1];
  if (!encoded) throw new Error('SIWE has no ReCap resource');
  return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')).att;
}

describe('prepareDelegationSession — raw encryption grants (TC-598)', () => {
  test('signs decrypt as a top-level network resource beside the space resources', () => {
    const result = prepare(secretRequest());
    if (process.env.PRINT_SIWE) console.log(result.prepared.siwe);

    expect(recapAtt(result.prepared.siwe)).toEqual({
      [network]: { [DECRYPT]: [{}] },
      [`${space}/kv/vault/secrets/TC_FWD_TOKEN`]: { 'tinycloud.kv/get': [{}] },
      [`${space}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
    });
    expect(result.prepared.siwe).toContain(`'tinycloud.encryption': 'decrypt' for '${network}'`);
    // The raw entry does not change the session space.
    expect(result.spaceId).toBe(space);
    // The relayed grant shape reports the raw entry with space `encryption`.
    expect(parsePreparedRecap(result.prepared.siwe)).toContainEqual({
      service: 'encryption',
      space: 'encryption',
      path: network,
      actions: [DECRYPT],
    });
    expect(result.edited).toBe(false);
  });

  test('a raw entry without a space signs the same resources', () => {
    const { space: _omitted, ...rawWithoutSpace } = secretRequest()[1]!;
    const withoutSpace = prepare([secretRequest()[0]!, rawWithoutSpace, secretRequest()[2]!]);
    expect(recapAtt(withoutSpace.prepared.siwe)).toEqual(recapAtt(prepare(secretRequest()).prepared.siwe));
  });

  test('unchecking decrypt removes the network from the signed SIWE', () => {
    const baseline = prepare(secretRequest());
    const decryptKey = baseline.selectedActionKeys.find((key) => key.endsWith(`\0${DECRYPT}`));
    expect(decryptKey).toBe(`tinycloud.encryption\0encryption\0${network}\0${DECRYPT}`);

    const narrowed = prepare(secretRequest(), baseline.selectedActionKeys.filter((key) => key !== decryptKey));
    expect(narrowed.edited).toBe(true);
    expect(narrowed.selectedActionKeys).not.toContain(decryptKey);
    expect(Object.keys(recapAtt(narrowed.prepared.siwe)).sort()).toEqual([
      `${space}/capabilities`,
      `${space}/kv/vault/secrets/TC_FWD_TOKEN`,
    ]);
    expect(narrowed.prepared.siwe).not.toContain('urn:tinycloud:encryption:');
  });

  test('a narrowed session that keeps decrypt still signs it as a raw resource', () => {
    const baseline = prepare(secretRequest());
    const narrowed = prepare(
      secretRequest(),
      baseline.selectedActionKeys.filter((key) => !key.endsWith('\0tinycloud.kv/get')),
    );
    expect(narrowed.edited).toBe(true);
    expect(recapAtt(narrowed.prepared.siwe)).toEqual({
      [network]: { [DECRYPT]: [{}] },
      [`${space}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
    });
  });

  function refusal(permissions: DelegationPermissionEntry[]): DelegateRequestError {
    let error: unknown;
    try {
      prepare(permissions);
    } catch (caught) {
      error = caught;
    }
    if (!(error instanceof DelegateRequestError)) throw new Error(`expected a DelegateRequestError, got ${String(error)}`);
    expect(error.code).toBe('invalid_permissions');
    return error;
  }

  test('refuses an encryption network the signer does not own before signing', () => {
    const foreign = [
      `urn:tinycloud:encryption:did:pkh:eip155:1:0x0000000000000000000000000000000000000001:default`,
      `urn:tinycloud:encryption:did:pkh:eip155:10:${address}:default`,
      `urn:tinycloud:encryption:did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK:default`,
      `urn:tinycloud:encryption:${ownerDid}`,
    ];
    for (const path of foreign) {
      expect(refusal(secretRequest({ path })).details?.[0]?.path, path).toBe('permissions[1].path');
    }
  });

  test('grants only decrypt on a raw network', () => {
    const refused = [
      ['tinycloud.encryption/network.revoke'],
      ['tinycloud.encryption/network.create'],
      ['tinycloud.kv/put'],
      [DECRYPT, 'tinycloud.encryption/network.revoke'],
    ];
    for (const actions of refused) {
      expect(refusal(secretRequest({ actions })).details?.[0]?.path, actions.join()).toMatch(/^permissions\[1\]\.actions\[\d\]$/);
    }
    expect(refusal(secretRequest({ actions: [] })).details?.[0]?.path).toBe('permissions[1].actions');
  });

  test('requires the SDK network-name rule', () => {
    for (const name of ['*', 'a/b', 'Default', '-default', 'de fault', 'a:b', '']) {
      const error = refusal(secretRequest({ path: `urn:tinycloud:encryption:${ownerDid}:${name}` }));
      expect(error.details?.[0]?.path, name).toBe('permissions[1].path');
    }
    const named = `urn:tinycloud:encryption:${ownerDid}:team-2`;
    expect(Object.keys(recapAtt(prepare(secretRequest({ path: named })).prepared.siwe))).toContain(named);
  });

  test('treats the short service name "encryption" as the same raw network', () => {
    const short = prepare(secretRequest({ service: 'encryption' }));
    expect(recapAtt(short.prepared.siwe)).toEqual(recapAtt(prepare(secretRequest()).prepared.siwe));
    const foreign = `urn:tinycloud:encryption:did:pkh:eip155:1:0x0000000000000000000000000000000000000001:default`;
    expect(refusal(secretRequest({ service: 'encryption', path: foreign })).details?.[0]?.path).toBe('permissions[1].path');
  });

  test('refuses a raw entry that claims a space other than encryption', () => {
    expect(() => prepare(secretRequest({ space }))).toThrow('must be "encryption" or absent');
  });
});

// TC-2349: the CLI's `builtin:share-publishing` manifest asks to decrypt the owner's `share/` key folder. On this
// route that is the ONE tail a raw encryption path may carry besides a bare network: `<network>/share/`, decrypt only,
// owner-bound. Anything else after the network name stays refused.
describe('prepareDelegationSession: the share/ folder of an owned encryption network (TC-2349)', () => {
  const folder = `${network}/share/`;

  test('signs decrypt on <network>/share/ as a raw ReCap resource and reports it back as the same urn', () => {
    const result = prepare(secretRequest({ path: folder }));
    expect(recapAtt(result.prepared.siwe)[folder]).toEqual({ [DECRYPT]: [{}] });
    expect(parsePreparedRecap(result.prepared.siwe)).toContainEqual({
      service: 'encryption',
      space: 'encryption',
      path: folder,
      actions: [DECRYPT],
    });
  });

  test('a named network keeps working with and without the folder', () => {
    const named = `urn:tinycloud:encryption:${ownerDid}:team-2`;
    expect(Object.keys(recapAtt(prepare(secretRequest({ path: `${named}/share/` })).prepared.siwe))).toContain(`${named}/share/`);
    expect(Object.keys(recapAtt(prepare(secretRequest({ path: named })).prepared.siwe))).toContain(named);
  });

  test('unchecking it removes the folder from the signed SIWE', () => {
    const baseline = prepare(secretRequest({ path: folder }));
    const key = baseline.selectedActionKeys.find((candidate) => candidate.includes(folder));
    expect(key).toBeDefined();
    const narrowed = prepare(secretRequest({ path: folder }), baseline.selectedActionKeys.filter((candidate) => candidate !== key));
    expect(narrowed.prepared.siwe).not.toContain('urn:tinycloud:encryption:');
  });

  function refusal(permissions: DelegationPermissionEntry[]): DelegateRequestError {
    let error: unknown;
    try {
      prepare(permissions);
    } catch (caught) {
      error = caught;
    }
    if (!(error instanceof DelegateRequestError)) throw new Error(`expected a DelegateRequestError, got ${String(error)}`);
    expect(error.code).toBe('invalid_permissions');
    return error;
  }

  test('refuses every other tail after the network name', () => {
    const tails = [
      'share', // no trailing slash: an exact key, not the folder
      'share//',
      'share/x/',
      'share/..',
      'share/../',
      'share/../other/',
      'share/%2e%2e/',
      'share/ /',
      'share/\\',
      'Share/',
      'shares/',
      'other/',
      'a/b',
      '/share/',
      '//share/',
      'share/0123456789abcdef0123456789abcdef/', // a per-share folder: not until something sends it
      'share/share/',
      '',
    ];
    for (const tail of tails) {
      const error = refusal(secretRequest({ path: `${network}/${tail}` }));
      expect(error.details?.[0]?.path, JSON.stringify(tail)).toBe('permissions[1].path');
    }
  });

  test('refuses a folder on a network the signer does not own, on another chain, or with a bad network name', () => {
    const foreign = [
      `urn:tinycloud:encryption:did:pkh:eip155:1:0x0000000000000000000000000000000000000001:default/share/`,
      `urn:tinycloud:encryption:did:pkh:eip155:10:${address}:default/share/`,
      `urn:tinycloud:encryption:did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK:default/share/`,
      `urn:tinycloud:encryption:${ownerDid}:Default/share/`,
      `urn:tinycloud:encryption:${ownerDid}:-default/share/`,
      `urn:tinycloud:encryption:${ownerDid}:/share/`,
      `urn:tinycloud:encryption:${ownerDid}:a:b/share/`,
    ];
    for (const path of foreign) {
      expect(refusal(secretRequest({ path })).details?.[0]?.path, path).toBe('permissions[1].path');
    }
  });

  test('grants only decrypt on the folder', () => {
    for (const actions of [['tinycloud.encryption/key.create'], [DECRYPT, 'tinycloud.encryption/key.create'], ['tinycloud.encryption/network.create'], ['tinycloud.kv/put'], []]) {
      expect(refusal(secretRequest({ path: folder, actions })).details?.[0]?.path, actions.join()).toMatch(/^permissions\[1\]\.actions/);
    }
  });

  test('a folder entry cannot carry another space', () => {
    expect(() => prepare(secretRequest({ path: folder, space }))).toThrow('must be "encryption" or absent');
  });
});

// The five entries `tinycloud auth login --manifest builtin:share-publishing` sends once the CLI has resolved them
// (@tinycloud/cli 1.5.2-beta.0 `SHARE_PUBLISHING_MANIFEST` + `resolvePermissionSpaces`): the encryption entry is
// permissions[4] and was refused before consent with "names an invalid encryption network".
describe('the CLI share-publishing request (TC-2349)', () => {
  const defaultSpace = `tinycloud:pkh:eip155:${chainId}:${address}:default`;
  const cliRequest: DelegationPermissionEntry[] = [
    { service: 'tinycloud.capabilities', space: defaultSpace, path: '', actions: ['tinycloud.capabilities/read'] },
    { service: 'tinycloud.kv', space: defaultSpace, path: 'xyz.tinycloud.share/shares/', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
    { service: 'tinycloud.kv', space: defaultSpace, path: 'shares/', actions: ['tinycloud.kv/get', 'tinycloud.kv/metadata', 'tinycloud.kv/put', 'tinycloud.kv/list'] },
    { service: 'tinycloud.kv', space: defaultSpace, path: 'artifacts/', actions: ['tinycloud.kv/get', 'tinycloud.kv/metadata', 'tinycloud.kv/put', 'tinycloud.kv/list'] },
    { service: 'tinycloud.encryption', space: 'encryption', path: `${network}/share/`, actions: [DECRYPT] },
  ];

  test('is prepared, and the signed ReCap carries the folder next to the four space resources', () => {
    const result = prepare(cliRequest);
    const att = recapAtt(result.prepared.siwe);
    expect(att[`${network}/share/`]).toEqual({ [DECRYPT]: [{}] });
    expect(Object.keys(att).filter((resource) => resource.startsWith('urn:tinycloud:encryption:'))).toEqual([`${network}/share/`]);
    expect(result.spaceId).toBe(defaultSpace);
  });
});
