import { describe, expect, test } from 'bun:test';
import { buildStatements, parseCapabilityReview } from '@openkey/capability-review';
import { DelegateRequestError } from '../routes/delegate-validation';
import { parsePreparedRecap, prepareDelegationSession, validatePermissions } from '../routes/delegate-session';

// TC-1424 / TC-2192: the public CLI permission encoding. Owner sessions may
// request share/ decrypt; a specific share keeps its exact leaf bytes.
const address = '0xA9F1299f56278AF2233e3547F52F94AC104F14A4';
const owner = `did:pkh:eip155:1:${address}`;
const network = `urn:tinycloud:encryption:${owner}:default`;
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const resource = `${network}/share/abc123`;
const DECRYPT = 'tinycloud.encryption/decrypt';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const anchor = { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] };
const decrypt = { service: 'tinycloud.encryption', space: 'encryption', path: resource, actions: [DECRYPT] };

function prepare(raw: Record<string, unknown> = {}) {
  return prepareDelegationSession({
    address, chainId: 1, prefix: 'default', jwk, expiryMs: 3_600_000,
    permissions: validatePermissions([anchor, { ...decrypt, ...raw }]),
  });
}

function att(siwe: string) {
  const encoded = /^- urn:recap:(.+)$/m.exec(siwe)![1]!;
  return JSON.parse(Buffer.from(encoded, 'base64url').toString()).att;
}

function review(message: string) {
  return parseCapabilityReview({
    message, editable: true,
    signer: { label: 'Managed key', address, chainId: 1, provenance: 'managed' },
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'TinyCloud CLI', verifiedOrigin: 'https://cli.tinycloud.xyz',
      appId: null, manifestName: null, manifestNameProvenance: 'none',
      manifestId: null, manifestIdProvenance: 'none', manifestDigest: null,
      domainWarning: false, originWarning: false,
    },
  });
}

function refusal(raw: Record<string, unknown>) {
  try { prepare(raw); } catch (error) {
    expect(error).toBeInstanceOf(DelegateRequestError);
    expect((error as DelegateRequestError).code).toBe('invalid_permissions');
    return error as DelegateRequestError;
  }
  throw new Error('Expected permission refusal');
}

describe('exact share decrypt permissions', () => {
  test('preserves the exact top-level named-key resource and explicit decrypt', () => {
    const result = prepare();
    expect(att(result.prepared.siwe)).toEqual({
      [`${space}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
      [resource]: { [DECRYPT]: [{}] },
    });
    expect(parsePreparedRecap(result.prepared.siwe)).toContainEqual({
      service: 'encryption', space: 'encryption', path: resource, actions: [DECRYPT],
    });
    expect(result.selectedActionKeys).toContain(`tinycloud.encryption\0encryption\0${resource}\0${DECRYPT}`);
  });

  test('removing decrypt leaves only the required capabilities anchor', () => {
    const baseline = prepare();
    const narrowed = prepareDelegationSession({
      address, chainId: 1, prefix: 'default', jwk, expiryMs: 3_600_000,
      permissions: [anchor, decrypt],
      actionKeys: baseline.selectedActionKeys.filter((key) => !key.endsWith(`\0${DECRYPT}`)),
    });
    expect(att(narrowed.prepared.siwe)).toEqual({
      [`${space}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
    });
  });

  test('renders one plain decrypt line for the exact share leaf', () => {
    const model = review(prepare().prepared.siwe);
    const grant = model.permissions.find((entry) => entry.service === 'tinycloud.encryption')!;
    expect(grant.ownedBySelf).toBe(true);
    expect(buildStatements(grant).map((row) => row.primaryText)).toEqual(['Open this shared file']);
  });

  const refusedPaths = [
    `${resource}/`, `${resource}/child`,
    `${network}/share`, `${network}/`, `${network}/root`,
    `${network}/apps/`, `${network}/apps/demo/key`,
    `${network}/share/*`, `${network}/share/abc*`, `${network}/share//abc123`,
    `${network}/share/../abc123`, `${network}/share/./abc123`,
    `${resource}%2Fchild`, `${network}/share%2Fabc123`, `${network}/share/%61bc123`,
    `${network}/share/ABC123`, `${resource}?x=1`, `${resource}#f`,
    `${network}/share/${'a'.repeat(65)}`,
    `${resource}\n`, `${resource}\r\n`,
    `urn:tinycloud:encryption:${owner}:other/share/abc123`,
    `urn:tinycloud:encryption:did:pkh:eip155:10:${address}:default/share/abc123`,
    `urn:tinycloud:encryption:did:pkh:eip155:1:0x0000000000000000000000000000000000000001:default/share/abc123`,
    `urn:tinycloud:encryption:${owner.toLowerCase()}:default/share/abc123`,
  ];
  for (const path of refusedPaths) {
    test(`refuses neighbouring path ${path}`, () => {
      expect(refusal({ path }).details?.[0]?.path).toBe('permissions[1].path');
    });
  }

  for (const actions of [[], ['tinycloud.encryption/encrypt'], ['tinycloud.encryption/key.create'],
    [DECRYPT, 'tinycloud.encryption/encrypt']]) {
    test(`refuses non-decrypt actions ${JSON.stringify(actions)}`, () => {
      expect(refusal({ actions }).details?.[0]?.path).toMatch(/^permissions\[1\]\.actions/);
    });
  }

  test('retains whole-network decrypt behavior', () => {
    const result = prepare({ path: network });
    expect(att(result.prepared.siwe)[network]).toEqual({ [DECRYPT]: [{}] });
  });

  test('accepts the node segment boundaries without admitting a descendant', () => {
    for (const id of ['a', '0', 'a-b_c.d', 'a'.repeat(64)]) {
      const path = `${network}/share/${id}`;
      expect(att(prepare({ path }).prepared.siwe)[path]).toEqual({ [DECRYPT]: [{}] });
    }
  });
});

describe('owner share-prefix decrypt permission', () => {
  const prefix = `${network}/share/`;

  test('prepares the canonical share prefix without broadening it to the network', () => {
    const result = prepare({ path: prefix });
    expect(att(result.prepared.siwe)).toEqual({
      [`${space}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
      [prefix]: { [DECRYPT]: [{}] },
    });
    expect(parsePreparedRecap(result.prepared.siwe)).toContainEqual({
      service: 'encryption', space: 'encryption', path: prefix, actions: [DECRYPT],
    });
  });

  test('owner can remove the prefix decrypt action before signing', () => {
    const baseline = prepare({ path: prefix });
    const narrowed = prepareDelegationSession({
      address, chainId: 1, prefix: 'default', jwk, expiryMs: 3_600_000,
      permissions: [anchor, { ...decrypt, path: prefix }],
      actionKeys: baseline.selectedActionKeys.filter((key) => !key.endsWith(`\0${DECRYPT}`)),
    });
    expect(att(narrowed.prepared.siwe)).toEqual({
      [`${space}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
    });
  });

  const neighbours = [
    `${network}/`, `${network}/sharex`, `${network}/sharex/`, `${network}/share`,
    `${network}/apps/`, `${network}/secrets/`, `${network}/share/abc123/`,
    `${network}/share//`, `${network}/share///`, `${network}//share/`,
    `${network}/share/./`, `${network}/share/../`, `${network}/x/../share/`,
    `${network}/share%2f`, `${network}/share%2F`, `${network}%2Fshare/`,
    `${network}/%73hare/`, `${network}/Share/`, `${network}/SHARE/`,
    `${network.replace(':default', ':Default')}/share/`,
    `${network}/share/?x=1`, `${network}/share/#f`, `${network}/share/*`,
    `${network.replace(':default', ':other')}/share/`,
    `${network.replace(':1:', ':10:')}/share/`,
    `${network.replace(address, '0x0000000000000000000000000000000000000001')}/share/`,
    `${network.replace(address, address.toLowerCase())}/share/`,
    `${network}/share/\n`, `${network}/share/\\`,
  ];
  for (const path of neighbours) {
    test(`refuses prefix neighbour ${JSON.stringify(path)}`, () => {
      expect(refusal({ path }).details?.[0]?.path).toBe('permissions[1].path');
    });
  }

  for (const ability of ['key.create', 'key.delete', 'key.block', 'key.unblock',
    'network.create', 'network.revoke', 'encrypt', '*']) {
    test(`refuses ${ability} on the prefix, alone and alongside decrypt`, () => {
      for (const actions of [[`tinycloud.encryption/${ability}`], [DECRYPT, `tinycloud.encryption/${ability}`]]) {
        expect(refusal({ path: prefix, actions }).details?.[0]?.path).toMatch(/^permissions\[1\]\.actions/);
      }
    });
  }
});
