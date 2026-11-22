// The owner's default/share/ folder keeps the app's length (not the one-hour start), and the renewal confirm for it is
// the same as for any other decryption: the box starts unticked and "Renew sensitive access?" is asked.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { parseCapabilityReview, type CapabilityGrant } from '../../../../packages/capability-review/src/index';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { isOnceTier, renewalNeedsSensitiveConfirm, renewalStartsTicked } from './renewal-default';
import { onceDefaultExpiryMs } from './approval-expiry';

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const D = 86_400_000;

function grants(att: Record<string, Record<string, unknown[]>>): CapabilityGrant[] {
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)]),
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'share.example', verifiedOrigin: 'https://share.example', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
  }).permissions;
}

const shareFolder = grants({ [`${NETWORK}/share/`]: { 'tinycloud.encryption/key.create': [{}], 'tinycloud.encryption/decrypt': [{}] } });
const wholeNetwork = grants({ [NETWORK]: { 'tinycloud.encryption/decrypt': [{}] } });

describe('a request for the share/ folder', () => {
  test('is not the one-hour tier, so the length the app asked for stands', () => {
    expect(isOnceTier(shareFolder)).toBe(false);
    expect(onceDefaultExpiryMs(isOnceTier(shareFolder), 7 * D)).toBeNull();
    expect(onceDefaultExpiryMs(isOnceTier(wholeNetwork), 7 * D)).toBe(3_600_000);
  });

  test('asks "Renew sensitive access?" and its box starts unticked', () => {
    expect(renewalNeedsSensitiveConfirm(shareFolder)).toBe(true);
    expect(renewalStartsTicked('standing', shareFolder)).toBe(false);
  });

  test('beside a whole-network decrypt is the one-hour tier', () => {
    expect(isOnceTier([...shareFolder, ...wholeNetwork])).toBe(true);
  });
});
