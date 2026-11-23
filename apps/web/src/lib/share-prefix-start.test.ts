// The owner's own default/share/ folder keeps the app's length (not the one-hour start) and renews like any other
// working access: the box starts ticked for a standing request and "Renew sensitive access?" is not asked.
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
const secretsFolder = grants({ [`${NETWORK}/secrets/`]: { 'tinycloud.encryption/decrypt': [{}] } });
const exactShareKey = grants({ [`${NETWORK}/share/abc123`]: { 'tinycloud.encryption/decrypt': [{}] } });
const otherOwnersShareFolder = grants({
  [`urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:0x2222222222222222222222222222222222222222:default/share/`]: {
    'tinycloud.encryption/decrypt': [{}],
  },
});

describe('a request for the share/ folder', () => {
  test('is not the one-hour tier, so the length the app asked for stands', () => {
    expect(isOnceTier(shareFolder)).toBe(false);
    expect(onceDefaultExpiryMs(isOnceTier(shareFolder), 7 * D)).toBeNull();
    expect(onceDefaultExpiryMs(isOnceTier(wholeNetwork), 7 * D)).toBe(3_600_000);
  });

  test('asks nothing to renew, and the box starts ticked for a standing request only', () => {
    expect(renewalNeedsSensitiveConfirm(shareFolder)).toBe(false);
    expect(renewalStartsTicked('standing', shareFolder)).toBe(true);
    expect(renewalStartsTicked('task', shareFolder)).toBe(false);
    expect(renewalStartsTicked(undefined, shareFolder)).toBe(false);
  });

  test('beside a secret, an exact share key or the whole network asks "Renew sensitive access?"', () => {
    for (const other of [secretsFolder, exactShareKey, wholeNetwork]) {
      expect(renewalNeedsSensitiveConfirm([...shareFolder, ...other])).toBe(true);
      expect(renewalStartsTicked('standing', [...shareFolder, ...other])).toBe(false);
    }
  });

  test('under another owner, or on its own as a secrets folder, an exact key or the whole network, asks it', () => {
    for (const asked of [otherOwnersShareFolder, secretsFolder, exactShareKey, wholeNetwork]) {
      expect(renewalNeedsSensitiveConfirm(asked)).toBe(true);
      expect(renewalStartsTicked('standing', asked)).toBe(false);
    }
  });

  test('beside a whole-network decrypt is the one-hour tier', () => {
    expect(isOnceTier([...shareFolder, ...wholeNetwork])).toBe(true);
  });
});
