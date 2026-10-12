// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { defaultSelection, parseCapabilityReview } from '@openkey/capability-review';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { nativeAccessSummary } from './native-access';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:applications`;

function review(resources: Record<string, Record<string, unknown[]>>) {
  const message = [
    'openkey.so wants you to sign in with your Ethereum account:', address, '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-07T04:00:00.000Z',
    'Expiration Time: 2026-10-07T05:00:00.000Z', 'Resources:', `- ${makeRecapResource(resources)}`,
  ].join('\n');
  const model = parseCapabilityReview({
    message,
    signer: { label: 'Canonical OpenKey key', address, chainId: 1, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'test' },
    reason: { text: '', source: 'none' },
    requester: { displayName: 'Exo', verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none',
      manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false },
  });
  return { model, selection: defaultSelection(model) };
}

describe('nativeAccessSummary', () => {
  test('reading and saving the app data is one plain sentence with no warning', () => {
    const { model, selection } = review({
      [`${space}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
      [`${space}/kv/xyz.tinycloud.tinychat/threads/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] },
    });
    expect(nativeAccessSummary(model, selection, 'Exo')).toEqual({ sentence: 'Exo will be able to read and save your Exo data.', warnings: [] });
  });

  test('follows the current selection', () => {
    const { model } = review({
      [`${space}/kv/xyz.tinycloud.tinychat/threads/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] },
    });
    const readOnly = new Set(model.permissions.flatMap((grant) => grant.actions).filter((action) => action.ability.endsWith('/get')).map((action) => action.id));
    expect(nativeAccessSummary(model, readOnly, 'Exo').sentence).toBe('Exo will be able to read your Exo data.');
  });

  test('an empty selection never claims data access', () => {
    const { model } = review({ [`${space}/kv/a/`]: { 'tinycloud.kv/get': [{}] } });
    expect(nativeAccessSummary(model, new Set(), 'Exo').sentence).toBe('Exo will be able to use your TinyCloud space.');
  });
});
