import { describe, expect, it, beforeEach } from 'bun:test';
import {
  _resetAuthorizationContextStoreForTests,
  consumeAuthorizationContext,
  digestAbilities,
  digestImmutableFields,
  digestJwk,
  issueAuthorizationContext,
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
});
