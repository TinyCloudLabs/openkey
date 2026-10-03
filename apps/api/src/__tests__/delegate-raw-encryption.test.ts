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

  test('refuses an encryption network the signer does not own before signing', () => {
    const foreign = [
      `urn:tinycloud:encryption:did:pkh:eip155:1:0x0000000000000000000000000000000000000001:default`,
      `urn:tinycloud:encryption:did:pkh:eip155:10:${address}:default`,
      `urn:tinycloud:encryption:did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK:default`,
      `urn:tinycloud:encryption:${ownerDid}`,
    ];
    for (const path of foreign) {
      let error: unknown;
      try {
        prepare(secretRequest({ path }));
      } catch (caught) {
        error = caught;
      }
      expect(error, path).toBeInstanceOf(DelegateRequestError);
      expect((error as DelegateRequestError).code).toBe('invalid_permissions');
      expect((error as DelegateRequestError).details?.[0]?.path).toBe('permissions[1].path');
    }
  });

  test('refuses a raw entry that claims a space other than encryption', () => {
    expect(() => prepare(secretRequest({ space }))).toThrow('must be "encryption" or absent');
  });
});
