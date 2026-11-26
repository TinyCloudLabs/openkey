// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { parseCapabilityReview } from '@openkey/capability-review';
import { REAL_RECAP_BOOTSTRAP } from '../../../../packages/capability-review/test/fixtures/index';
import { withLiveRequester } from './live-requester-model';

const model = (displayName: string) => parseCapabilityReview({
  message: REAL_RECAP_BOOTSTRAP,
  signer: { label: 'Key 0', address: '0x5B38Da6a701c568545dCfcB03FcB875f56beddC4', chainId: 1, provenance: 'managed' },
  editable: true,
  metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
  reason: { text: '', source: 'none' },
  requester: {
    displayName, verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none', manifestId: null,
    manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false,
  },
});

describe('withLiveRequester', () => {
  test('a name frozen into the model is dropped when the requester is no longer named', () => {
    const frozen = model('TinyCloud One');
    expect(frozen.requester.displayName).toBe('TinyCloud One');
    expect(withLiveRequester(frozen, null)!.requester.displayName).toBe('');
  });

  test('the live name replaces the frozen one, and the rest of the model is the same', () => {
    const frozen = model('TinyCloud One');
    const live = withLiveRequester(frozen, { displayName: 'Example App' })!;
    expect(live.requester.displayName).toBe('Example App');
    expect(live.rawMessage).toBe(frozen.rawMessage);
    expect(live.permissions).toBe(frozen.permissions);
    expect(live.requester.verifiedOrigin).toBe(frozen.requester.verifiedOrigin);
    expect(frozen.requester.displayName).toBe('TinyCloud One');
  });

  test('no model gives no model', () => {
    expect(withLiveRequester(null, { displayName: 'Example App' })).toBeNull();
  });
});
