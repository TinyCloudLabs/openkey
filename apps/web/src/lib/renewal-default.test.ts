// TC-2933: whether the renewal box starts ticked follows spec #322: standing purpose (D11/D12), never the Once tier (D7).
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { parseCapabilityReview, type CapabilityReviewModel } from '../../../../packages/capability-review/src/index';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { isOnceTier, renewalStartsTicked } from './renewal-default';

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;

function grants(att: Record<string, Record<string, unknown[]>>): CapabilityReviewModel['permissions'] {
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)]),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'courier.tinycloud.xyz', verifiedOrigin: 'https://courier.tinycloud.xyz', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  }).permissions;
}

const ordinary = grants({ [`${FIXTURE_META.ownSpace}/kv/courier/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] } });
const decrypt = grants({
  [`${FIXTURE_META.ownSpace}/kv/courier/`]: { 'tinycloud.kv/get': [{}] },
  [`urn:tinycloud:encryption:${OWNER}:default/apps/xyz.tinycloud.courier/`]: { 'tinycloud.encryption/decrypt': [{}] },
});
const secret = grants({ [`${FIXTURE_META.ownSpace}/kv/vault/secrets/DEPLOY_KEY`]: { 'tinycloud.kv/get': [{}] } });

describe('the renewal box starts ticked', () => {
  test('only for a signed standing purpose', () => {
    expect(renewalStartsTicked('standing', ordinary)).toBe(true);
    expect(renewalStartsTicked('task', ordinary)).toBe(false);
    expect(renewalStartsTicked(undefined, ordinary)).toBe(false);
    expect(renewalStartsTicked('Standing', ordinary)).toBe(false);
  });

  test('never in the Once tier (decrypt or reading a secret), whatever the purpose', () => {
    expect(isOnceTier(ordinary)).toBe(false);
    expect(isOnceTier(decrypt)).toBe(true);
    expect(isOnceTier(secret)).toBe(true);
    expect(renewalStartsTicked('standing', decrypt)).toBe(false);
    expect(renewalStartsTicked('standing', secret)).toBe(false);
  });
});
