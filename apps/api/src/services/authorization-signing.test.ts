import { describe, expect, it, beforeEach } from 'bun:test';
import {
  _resetAuthorizationContextStoreForTests,
  consumeAuthorizationContext,
  consumePreviewApproval,
  digestAbilities,
  digestFullRecapAttenuation,
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

// Sol final continuation contract requirement 3: caveat semantics must be
// EXACT for every surviving (resource, ability). The consume path exercises
// `attenuationSubsetFailure` via `candidateAttenuation`/`baselineAttenuation`.
describe('caveat semantics — surviving abilities require exact multiset equality', () => {
  beforeEach(() => {
    _resetAuthorizationContextStoreForTests();
  });

  const resource = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default/kv';
  const abilityGet = 'tinycloud.kv/get';
  const abilityPut = 'tinycloud.kv/put';

  function issueWithBaseline(baseline: Record<string, Record<string, unknown[]>>) {
    const input = {
      ...baseIssueInput(),
      baselineAbilitiesDigest: digestFullRecapAttenuation(baseline),
    };
    return issueAuthorizationContext(input);
  }

  it('accepts a candidate identical to baseline (no caveat drift)', () => {
    const baseline = {
      [resource]: { [abilityGet]: [{}], [abilityPut]: [{ maxSize: 100 }] },
    };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: baseline,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(true);
  });

  it('accepts a candidate that removes an entire ability from a surviving resource', () => {
    const baseline = {
      [resource]: { [abilityGet]: [{}], [abilityPut]: [{}] },
    };
    const candidate = {
      [resource]: { [abilityGet]: [{}] },
    };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: candidate,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(true);
  });

  it('accepts a candidate that removes an entire resource', () => {
    const otherResource = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default/sql';
    const baseline = {
      [resource]: { [abilityGet]: [{}] },
      [otherResource]: { 'tinycloud.sql/read': [{}] },
    };
    const candidate = { [resource]: { [abilityGet]: [{}] } };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: candidate,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(true);
  });

  it('rejects a candidate that REMOVES a caveat from a surviving ability', () => {
    const baseline = {
      [resource]: { [abilityGet]: [{ maxAge: 60 }, { minSize: 1 }] },
    };
    const candidate = {
      [resource]: { [abilityGet]: [{ maxAge: 60 }] }, // dropped the minSize caveat
    };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: candidate,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe('candidate-broadens-baseline');
      // The message may cite "removed" (per-caveat drift) or "differ"
      // (multiset size mismatch) depending on which check surfaced first.
      expect(res.message).toMatch(/removed|differ/);
    }
  });

  it('rejects a candidate that ADDS a caveat to a surviving ability', () => {
    const baseline = { [resource]: { [abilityGet]: [{ maxAge: 60 }] } };
    const candidate = {
      [resource]: { [abilityGet]: [{ maxAge: 60 }, { extraCaveat: true }] },
    };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: candidate,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe('candidate-broadens-baseline');
      expect(res.message).toMatch(/added|differ/);
    }
  });

  it('rejects a candidate that CHANGES a caveat on a surviving ability', () => {
    const baseline = { [resource]: { [abilityGet]: [{ maxAge: 60 }] } };
    const candidate = {
      [resource]: { [abilityGet]: [{ maxAge: 3600 }] }, // different value
    };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: candidate,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe('candidate-broadens-baseline');
  });

  it('rejects a candidate that CHANGES DUPLICATE COUNT on a surviving ability', () => {
    // Baseline has two identical `{}` caveats; candidate collapses to one.
    // Even though `{}` is the ReCap "no restriction" placeholder, the wire
    // multiset MUST agree — collapsing the count is a divergence.
    const baseline = { [resource]: { [abilityGet]: [{}, {}] } };
    const candidate = { [resource]: { [abilityGet]: [{}] } };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: candidate,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe('candidate-broadens-baseline');
      expect(res.message).toMatch(/duplicate count decreased/);
    }
  });

  it('rejects a candidate that INCREASES DUPLICATE COUNT on a surviving ability', () => {
    const baseline = { [resource]: { [abilityGet]: [{}] } };
    const candidate = { [resource]: { [abilityGet]: [{}, {}] } };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: candidate,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe('candidate-broadens-baseline');
      expect(res.message).toMatch(/duplicate count increased/);
    }
  });

  it('rejects an ability not in baseline (broadening)', () => {
    const baseline = { [resource]: { [abilityGet]: [{}] } };
    const candidate = { [resource]: { [abilityGet]: [{}], [abilityPut]: [{}] } };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: candidate,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe('candidate-broadens-baseline');
      expect(res.message).toContain('not in baseline');
    }
  });

  it('rejects a resource not in baseline (broadening)', () => {
    const baseline = { [resource]: { [abilityGet]: [{}] } };
    const otherResource = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default/sql';
    const candidate = {
      [resource]: { [abilityGet]: [{}] },
      [otherResource]: { 'tinycloud.sql/read': [{}] },
    };
    const { token } = issueWithBaseline(baseline);
    const res = consumeAuthorizationContext({
      ...baseConsumeInput(token),
      candidateAttenuation: candidate,
      baselineAttenuation: baseline,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBe('candidate-broadens-baseline');
      expect(res.message).toContain('not in baseline');
    }
  });
});
