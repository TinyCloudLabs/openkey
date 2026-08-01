import { describe, expect, it, beforeEach } from 'bun:test';
import {
  _resetAuthorizationContextStoreForTests,
  consumeAuthorizationContext,
  consumePreviewApproval,
  digestAbilities,
  digestImmutableFields,
  digestJwk,
  issueAuthorizationContext,
  issuePreviewApproval,
} from './authorization-signing';

const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAA' };
const abilities = { kv: { '': ['tinycloud.kv/get', 'tinycloud.kv/put'] } };
const immutable = {
  address: '0x1111111111111111111111111111111111111111',
  chainId: 1,
  domain: 'cli.tinycloud.xyz',
  issuedAt: '2026-07-31T00:00:00.000Z',
  expirationTime: '2026-08-07T00:00:00.000Z',
  spaceId: 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default',
  nonce: 'abcdef123456',
};

function baseIssueInput() {
  return {
    userId: 'user-1',
    keyId: 'key-1',
    keyAddress: immutable.address,
    jwk,
    host: 'https://node.tinycloud.xyz',
    spaceId: immutable.spaceId,
    baselineAbilitiesDigest: digestAbilities(abilities),
    immutableFieldsDigest: digestImmutableFields(immutable),
    allowedActionIds: new Set(['a1', 'a2', 'req']),
    initialSelectionActionIds: new Set(['a1', 'a2', 'req']),
    expirationTime: immutable.expirationTime,
  };
}

function baseConsumeInput(token: string) {
  return {
    token,
    userId: 'user-1',
    keyId: 'key-1',
    keyAddress: immutable.address,
    jwk,
    host: 'https://node.tinycloud.xyz',
    spaceId: immutable.spaceId,
    selectedActionIds: new Set(['a1', 'req']),
    candidateImmutableFieldsDigest: digestImmutableFields(immutable),
    requiredActionIds: new Set(['req']),
  };
}

describe('authorization-signing', () => {
  beforeEach(() => {
    _resetAuthorizationContextStoreForTests();
  });

  it('accepts a matching context', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext(baseConsumeInput(token));
    expect(result.ok).toBe(true);
  });

  it('is single-use — replay is rejected', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const first = consumeAuthorizationContext(baseConsumeInput(token));
    expect(first.ok).toBe(true);
    const second = consumeAuthorizationContext(baseConsumeInput(token));
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.error).toBe('context-not-found');
  });

  it('rejects a different user', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      userId: 'user-2',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('user-mismatch');
  });

  it('rejects a different JWK', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      jwk: { ...jwk, x: 'BBB' },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('jwk-mismatch');
  });

  it('rejects a different host', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      host: 'https://evil.example',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('host-mismatch');
  });

  it('rejects an altered immutable field', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateImmutableFieldsDigest: digestImmutableFields({
        ...immutable,
        nonce: 'tampered',
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('immutable-fields-changed');
  });

  it('rejects selecting an action outside baseline', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      selectedActionIds: new Set(['not-in-baseline', 'req']),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('action-not-in-baseline');
  });

  it('rejects removing a required action', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      selectedActionIds: new Set(['a1']), // req dropped
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('required-action-missing');
  });

  it('stable-orders the JWK digest', () => {
    const a = digestJwk({ kty: 'OKP', crv: 'Ed25519', x: 'AAA' });
    const b = digestJwk({ x: 'AAA', crv: 'Ed25519', kty: 'OKP' });
    expect(a).toBe(b);
  });

  it('accepts a matching candidate abilities digest', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAbilitiesDigest: digestAbilities(abilities),
    });
    expect(result.ok).toBe(true);
  });

  it('rejects a mismatched candidate abilities digest', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAbilitiesDigest: digestAbilities({
        kv: { '': ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del'] },
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('baseline-digest-mismatch');
  });

  it('skips candidate abilities check when null', () => {
    const { token } = issueAuthorizationContext(baseIssueInput());
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAbilitiesDigest: null,
    });
    expect(result.ok).toBe(true);
  });

  // Sol CRITICAL-2: /complete may only sign a subset of the initial
  // selection. An action allowed by the baseline but removed from the
  // initial selection MUST be rejected.
  it('rejects a selection that adds an action removed from the initial selection', () => {
    const issue = {
      ...baseIssueInput(),
      // The baseline (allowed) permits a1/a2/req, but the user picked
      // only a1 + req initially. /complete cannot now sign a2.
      initialSelectionActionIds: new Set(['a1', 'req']),
    };
    const { token } = issueAuthorizationContext(issue);
    const result = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      selectedActionIds: new Set(['a1', 'a2', 'req']),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('action-not-in-initial-selection');
  });
});

// Sol CRITICAL-1: preview-approval token seals (selection, bytes) so
// /authorize-sign cannot sign different bytes or a different selection
// than the preview evaluated.
describe('preview-approval tokens', () => {
  beforeEach(() => {
    _resetAuthorizationContextStoreForTests();
  });

  it('consumes a matching (context, selection, bytes) triple', () => {
    const previewBytes = 'server-authoritative-signed-bytes-v1';
    const { token } = issuePreviewApproval({
      authorizationContextToken: 'ctx-abc',
      userId: 'u1',
      keyAddress: '0x1111111111111111111111111111111111111111',
      selectedActionIds: new Set(['a1', 'a2']),
      signedMessage: previewBytes,
    });
    const res = consumePreviewApproval({
      token,
      authorizationContextToken: 'ctx-abc',
      userId: 'u1',
      selectedActionIds: new Set(['a2', 'a1']), // order-independent
      candidateSignedMessage: previewBytes,
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.signedMessage).toBe(previewBytes);
  });

  it('is single-use — replay is rejected', () => {
    const { token } = issuePreviewApproval({
      authorizationContextToken: 'ctx-x',
      userId: 'u1',
      keyAddress: '0x1111111111111111111111111111111111111111',
      selectedActionIds: new Set(['x']),
      signedMessage: 'bytes-x',
    });
    const first = consumePreviewApproval({
      token,
      authorizationContextToken: 'ctx-x',
      userId: 'u1',
      selectedActionIds: new Set(['x']),
      candidateSignedMessage: 'bytes-x',
    });
    expect(first.ok).toBe(true);
    const second = consumePreviewApproval({
      token,
      authorizationContextToken: 'ctx-x',
      userId: 'u1',
      selectedActionIds: new Set(['x']),
      candidateSignedMessage: 'bytes-x',
    });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.error).toBe('preview-approval-not-found');
  });

  it('rejects a different bytes candidate', () => {
    const { token } = issuePreviewApproval({
      authorizationContextToken: 'ctx-y',
      userId: 'u1',
      keyAddress: '0x1111111111111111111111111111111111111111',
      selectedActionIds: new Set(['x']),
      signedMessage: 'previewed-bytes',
    });
    const res = consumePreviewApproval({
      token,
      authorizationContextToken: 'ctx-y',
      userId: 'u1',
      selectedActionIds: new Set(['x']),
      candidateSignedMessage: 'different-bytes',
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe('preview-approval-bytes-mismatch');
  });

  it('rejects a different selection', () => {
    const { token } = issuePreviewApproval({
      authorizationContextToken: 'ctx-z',
      userId: 'u1',
      keyAddress: '0x1111111111111111111111111111111111111111',
      selectedActionIds: new Set(['a', 'b']),
      signedMessage: 'bytes-z',
    });
    const res = consumePreviewApproval({
      token,
      authorizationContextToken: 'ctx-z',
      userId: 'u1',
      // Missing "b" — this is a narrowing at finalize.
      selectedActionIds: new Set(['a']),
      candidateSignedMessage: 'bytes-z',
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe('preview-approval-selection-mismatch');
  });

  it('rejects a different user', () => {
    const { token } = issuePreviewApproval({
      authorizationContextToken: 'ctx-w',
      userId: 'u1',
      keyAddress: '0x1111111111111111111111111111111111111111',
      selectedActionIds: new Set(['a']),
      signedMessage: 'bytes-w',
    });
    const res = consumePreviewApproval({
      token,
      authorizationContextToken: 'ctx-w',
      userId: 'u2',
      selectedActionIds: new Set(['a']),
      candidateSignedMessage: 'bytes-w',
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe('preview-approval-user-mismatch');
  });

  it('rejects a different context token', () => {
    const { token } = issuePreviewApproval({
      authorizationContextToken: 'ctx-v',
      userId: 'u1',
      keyAddress: '0x1111111111111111111111111111111111111111',
      selectedActionIds: new Set(['a']),
      signedMessage: 'bytes-v',
    });
    const res = consumePreviewApproval({
      token,
      authorizationContextToken: 'ctx-other',
      userId: 'u1',
      selectedActionIds: new Set(['a']),
      candidateSignedMessage: 'bytes-v',
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe('preview-approval-context-mismatch');
  });
});
