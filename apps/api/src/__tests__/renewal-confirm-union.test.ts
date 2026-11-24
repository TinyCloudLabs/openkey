// The approval screen asks "Renew sensitive access?" wherever any of three rules would:
// the grant reaches secret data or decryption, the grant is in the one-hour Once tier, or the
// API's renewal rule (`leaseReachesSecrets`) refuses an unconfirmed lease. The screen's `renewalNeedsSensitiveConfirm`
// must be at least that union, and never looser than the API. Each row is built into a real signed message by the WASM
// signer; the API reads its ReCap, the page reads the review model.
import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  grantIsBroadOnce,
  grantReachesSecretDataOrDecryption,
  parseCapabilityReview,
} from '../../../../packages/capability-review/src/index';
import { FIXTURE_META } from '../../../../packages/capability-review/test/fixtures/index';
import { isOnceTier, renewalNeedsSensitiveConfirm, renewalStartsTicked } from '../../../web/src/lib/renewal-default';
import { RenewalLeaseError, leaseReachesSecrets } from '../services/renewal-lease';

const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const VAULT = `${FIXTURE_META.ownSpace}/kv/vault/secrets`;

interface Row {
  name: string;
  att: Record<string, string[]>;
}

const ROWS: readonly Row[] = [
  { name: 'plain KV', att: { [`${FIXTURE_META.ownSpace}/kv/courier/`]: ['tinycloud.kv/get', 'tinycloud.kv/put'] } },
  { name: 'read one secret (KV)', att: { [`${VAULT}/DEPLOY_KEY`]: ['tinycloud.kv/get'] } },
  { name: 'write one secret (KV)', att: { [`${VAULT}/DEPLOY_KEY`]: ['tinycloud.kv/put'] } },
  { name: 'read the whole vault (KV, empty name)', att: { [`${VAULT}/`]: ['tinycloud.kv/get'] } },
  { name: 'decrypt on one secret', att: { [`${NETWORK}/secrets/a`]: ['tinycloud.encryption/decrypt'] } },
  { name: 'decrypt on the secrets/ prefix', att: { [`${NETWORK}/secrets/`]: ['tinycloud.encryption/decrypt'] } },
  { name: 'decrypt on an app prefix', att: { [`${NETWORK}/apps/xyz.tinycloud.courier/`]: ['tinycloud.encryption/decrypt'] } },
  { name: 'decrypt on the whole network', att: { [NETWORK]: ['tinycloud.encryption/decrypt'] } },
  { name: 'every ability on the whole network', att: { [NETWORK]: ['tinycloud.encryption/*'] } },
  { name: 'key.create on the secrets/ prefix', att: { [`${NETWORK}/secrets/`]: ['tinycloud.encryption/key.create'] } },
  { name: 'key.describe on one secret', att: { [`${NETWORK}/secrets/a`]: ['tinycloud.encryption/key.describe'] } },
  { name: 'key.create on the whole network', att: { [NETWORK]: ['tinycloud.encryption/key.create'] } },
  { name: 'an unknown encryption ability on one secret', att: { [`${NETWORK}/secrets/a`]: ['tinycloud.encryption/frobnicate'] } },
  { name: 'an unknown encryption ability on the whole network', att: { [NETWORK]: ['tinycloud.encryption/frobnicate'] } },
  { name: 'decrypt on a share key', att: { [`${NETWORK}/share/x`]: ['tinycloud.encryption/decrypt'] } },
  { name: 'decrypt on a key outside secrets/', att: { [`${NETWORK}/notes/a`]: ['tinycloud.encryption/decrypt'] } },
  { name: 'decrypt on an unparseable encryption resource', att: { [`urn:tinycloud:encryption:${OWNER}:Default/secrets/a`]: ['tinycloud.encryption/decrypt'] } },
];

/** The rows where the page asks but the API's `leaseReachesSecrets` would not refuse: asking more is the safe side. */
const ASKS_BEYOND_THE_API = [
  'read one secret (KV)',
  'write one secret (KV)',
  'read the whole vault (KV, empty name)',
  'decrypt on an app prefix',
  'decrypt on a share key',
  'decrypt on a key outside secrets/',
];

function signed(row: Row): string {
  const issuedAt = Date.parse('2026-11-22T00:00:00.000Z');
  return prepareSession({
    address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, domain: 'openkey.so', spaceId: FIXTURE_META.ownSpace, jwk,
    issuedAt: new Date(issuedAt).toISOString(), expirationTime: new Date(issuedAt + 7 * 86_400_000).toISOString(),
    abilities: {},
    rawAbilities: row.att,
  } as unknown as Parameters<typeof prepareSession>[0]).siwe;
}

function grantsOf(message: string) {
  return parseCapabilityReview({
    message,
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'app.example', verifiedOrigin: 'https://app.example', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  }).permissions;
}

/** The API's answer: `refuses` when an unconfirmed lease would be refused (a confirm needed, or the grant unreadable). */
function apiRefusesUnconfirmed(message: string): boolean {
  try {
    return leaseReachesSecrets(message);
  } catch (error) {
    expect(error).toBeInstanceOf(RenewalLeaseError);
    return true;
  }
}

describe('the renewal confirm is at least the union of the three rules', () => {
  for (const row of ROWS) {
    test(row.name, () => {
      const message = signed(row);
      const grants = grantsOf(message);
      const merged = renewalNeedsSensitiveConfirm(grants);
      // Any grant reaching secret data or decryption.
      if (grants.some(grantReachesSecretDataOrDecryption)) expect(merged).toBe(true);
      // The Once tier. It only places grants that reach secret data or decryption, so no shape is in it alone.
      if (grants.some(grantIsBroadOnce)) expect(grants.some(grantReachesSecretDataOrDecryption)).toBe(true);
      if (grants.some(grantIsBroadOnce)) expect(merged).toBe(true);
      if (isOnceTier(grants)) expect(merged).toBe(true);
      // Never looser than the API.
      if (apiRefusesUnconfirmed(message)) expect(merged).toBe(true);
      // The box never starts ticked where the confirm is asked.
      if (merged) expect(renewalStartsTicked('standing', grants)).toBe(false);
    });
  }

  test('the rows where the page asks but the API does not refuse are exactly the listed ones', () => {
    const beyond = ROWS.filter((row) => {
      const message = signed(row);
      return renewalNeedsSensitiveConfirm(grantsOf(message)) && !apiRefusesUnconfirmed(message);
    }).map((row) => row.name);
    expect(beyond).toEqual(ASKS_BEYOND_THE_API);
  });

  test('plain KV asks for nothing, and a standing request starts ticked', () => {
    const grants = grantsOf(signed(ROWS[0]!));
    expect(renewalNeedsSensitiveConfirm(grants)).toBe(false);
    expect(renewalStartsTicked('standing', grants)).toBe(true);
  });
});
