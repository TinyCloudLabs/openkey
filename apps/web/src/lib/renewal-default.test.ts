// The Once tier is narrow (broad secret or decryption access); the Sensitive
// tier that drives renewal opt-in is broad (any grant reaching secret data or
// decryption).
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { parseCapabilityReview, type CapabilityReviewModel } from '../../../../packages/capability-review/src/index';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { isOnceTier, isSensitiveTier, renewalStartsTicked } from './renewal-default';

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
// App-scoped encryption prefix (kind = "prefix"): sensitive but NOT broad-once.
const decrypt = grants({
  [`${FIXTURE_META.ownSpace}/kv/courier/`]: { 'tinycloud.kv/get': [{}] },
  [`urn:tinycloud:encryption:${OWNER}:default/apps/xyz.tinycloud.courier/`]: { 'tinycloud.encryption/decrypt': [{}] },
});
// Named secret: sensitive but NOT broad-once.
const secret = grants({ [`${FIXTURE_META.ownSpace}/kv/vault/secrets/DEPLOY_KEY`]: { 'tinycloud.kv/get': [{}] } });
// Whole-network decrypt (kind = "network"): broad-once.
const wholeNetworkDecrypt = grants({
  [`urn:tinycloud:encryption:${OWNER}:default`]: { 'tinycloud.encryption/decrypt': [{}] },
});
// Whole-vault KV read (empty name tail): broad-once.
const wholeVault = grants({ [`${FIXTURE_META.ownSpace}/kv/vault/secrets/`]: { 'tinycloud.kv/get': [{}] } });

describe('the renewal box starts ticked', () => {
  test('only for a signed standing purpose', () => {
    expect(renewalStartsTicked('standing', ordinary)).toBe(true);
    expect(renewalStartsTicked('task', ordinary)).toBe(false);
    expect(renewalStartsTicked(undefined, ordinary)).toBe(false);
    expect(renewalStartsTicked('Standing', ordinary)).toBe(false);
  });

  test('never for a Sensitive request (decrypt or reading a secret), whatever the purpose', () => {
    expect(renewalStartsTicked('standing', decrypt)).toBe(false);
    expect(renewalStartsTicked('standing', secret)).toBe(false);
    expect(renewalStartsTicked('standing', wholeNetworkDecrypt)).toBe(false);
    expect(renewalStartsTicked('standing', wholeVault)).toBe(false);
  });
});

describe('isOnceTier (narrowed: broad-only; drives the 1h expiry start)', () => {
  test('plain KV access is not broad-once', () => {
    expect(isOnceTier(ordinary)).toBe(false);
  });

  test('a named secret follows the app ask, so it is NOT broad-once', () => {
    expect(isOnceTier(secret)).toBe(false);
  });

  test('an app-scoped encryption prefix follows the app ask, so it is NOT broad-once', () => {
    expect(isOnceTier(decrypt)).toBe(false);
  });

  test('whole-network decrypt (bare network URN) is broad-once', () => {
    expect(isOnceTier(wholeNetworkDecrypt)).toBe(true);
  });

  test('whole-vault KV read (empty name tail) is broad-once', () => {
    expect(isOnceTier(wholeVault)).toBe(true);
  });
});

describe('isSensitiveTier (broad: drives renewal opt-in and the D7 confirm)', () => {
  test('plain KV access is not Sensitive', () => {
    expect(isSensitiveTier(ordinary)).toBe(false);
  });

  test('every grant that reaches secret data or decryption is Sensitive', () => {
    expect(isSensitiveTier(decrypt)).toBe(true);
    expect(isSensitiveTier(secret)).toBe(true);
    expect(isSensitiveTier(wholeNetworkDecrypt)).toBe(true);
    expect(isSensitiveTier(wholeVault)).toBe(true);
  });
});
