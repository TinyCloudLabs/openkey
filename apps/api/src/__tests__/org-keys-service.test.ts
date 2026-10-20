import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { recoverAddress, verifyMessage, type Hex } from 'viem';
import { OrgKeyRefusal, signOrgKeyMessage, type OrgKeySignInput } from '../services/org-keys';
import {
  asPrisma,
  assertionFor,
  challengeFor,
  ORIGIN,
  RP_ID,
  setupOrgKey,
} from './org-keys-fixtures';

const MESSAGE = 'Sign in to the org console, nonce 42';

async function signInput(
  ctx: Awaited<ReturnType<typeof setupOrgKey>>,
  message: string,
  assertionOptions: Parameters<typeof assertionFor>[2] = {},
  overrides: Partial<OrgKeySignInput> = {},
): Promise<OrgKeySignInput> {
  const challenge = challengeFor(ctx.key.keyId, ctx.key.grantId, message);
  return {
    userId: 'user_1',
    keyId: ctx.key.keyId,
    grantId: ctx.key.grantId,
    origin: ORIGIN,
    message,
    format: 'personal_sign',
    assertion: assertionFor(ctx.passkey, challenge, assertionOptions),
    rpID: RP_ID,
    expectedOrigin: ORIGIN,
    ...overrides,
  };
}

function sign(ctx: Awaited<ReturnType<typeof setupOrgKey>>, input: OrgKeySignInput) {
  return signOrgKeyMessage(asPrisma(ctx.db), ctx.tee, input);
}

async function expectRefusal(promise: Promise<unknown>, status: number, code: string) {
  const error = await promise.then(
    () => null,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(OrgKeyRefusal);
  expect(error).toMatchObject({ status, code });
}

describe('org key signing service', () => {
  test('signs under a fresh passkey and records one audit row with actor, grant, origin, and digest', async () => {
    const ctx = await setupOrgKey();
    const result = await sign(ctx, await signInput(ctx, MESSAGE));

    expect(result.address).toBe(ctx.key.address);
    expect(await verifyMessage({ address: ctx.key.address as Hex, message: MESSAGE, signature: result.signature })).toBe(
      true,
    );

    expect(ctx.state.audits).toHaveLength(1);
    expect(ctx.state.audits[0]).toMatchObject({
      keyId: ctx.key.keyId,
      grantId: ctx.key.grantId,
      actorUserId: 'user_1',
      origin: ORIGIN,
      messageDigest: createHash('sha256').update(MESSAGE, 'utf8').digest('hex'),
    });
    expect(ctx.state.passkeys[0]?.counter).toBe(1);
  });

  test('raw format signs the message bytes as the hash, not an EIP-191 digest', async () => {
    const ctx = await setupOrgKey();
    const rawHash = `0x${createHash('sha256').update('raw-bytes').digest('hex')}` as Hex;
    const result = await sign(ctx, await signInput(ctx, rawHash, {}, { format: 'raw' }));

    const recovered = await recoverAddress({ hash: rawHash, signature: result.signature });
    expect(recovered.toLowerCase()).toBe(ctx.key.address.toLowerCase());
  });

  test('refuses a malformed assertion before any passkey lookup', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);
    const malformed = { ...input.assertion, id: undefined } as unknown as OrgKeySignInput['assertion'];

    await expectRefusal(sign(ctx, { ...input, assertion: malformed }), 403, 'passkey_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses an assertion whose challenge was issued for a different message', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, 'message A');

    await expectRefusal(sign(ctx, { ...input, message: 'message B' }), 403, 'passkey_invalid');
    expect(ctx.state.audits).toHaveLength(0);
    expect(ctx.state.passkeys[0]?.counter).toBe(0);
  });

  test('binds the challenge to the key and the grant', async () => {
    const ctx = await setupOrgKey();
    const wrongKey = challengeFor('other_key', ctx.key.grantId, MESSAGE);
    const wrongGrant = challengeFor(ctx.key.keyId, 'other_grant', MESSAGE);

    const onKey = await signInput(ctx, MESSAGE);
    await expectRefusal(
      sign(ctx, { ...onKey, assertion: assertionFor(ctx.passkey, wrongKey) }),
      403,
      'passkey_invalid',
    );
    await expectRefusal(
      sign(ctx, { ...onKey, assertion: assertionFor(ctx.passkey, wrongGrant) }),
      403,
      'passkey_invalid',
    );
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses an assertion for a different origin', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE, { origin: 'https://evil.example' });

    await expectRefusal(sign(ctx, input), 403, 'passkey_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a user-verification-free assertion', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE, { userVerified: false });

    await expectRefusal(sign(ctx, input), 403, 'passkey_invalid');
  });

  test('refuses a signature counter that does not advance', async () => {
    const ctx = await setupOrgKey({ counter: 5 });
    const input = await signInput(ctx, MESSAGE, { counter: 1 });

    await expectRefusal(sign(ctx, input), 403, 'passkey_invalid');
    expect(ctx.state.passkeys[0]?.counter).toBe(5);
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a passkey that belongs to another user', async () => {
    const ctx = await setupOrgKey();
    ctx.state.passkeys[0] = { ...ctx.state.passkeys[0], userId: 'user_2' };

    await expectRefusal(sign(ctx, await signInput(ctx, MESSAGE)), 403, 'passkey_required');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses once the grant is revoked, even with a valid assertion', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);
    ctx.state.grants[0] = { ...ctx.state.grants[0], revokedAt: new Date() };

    await expectRefusal(sign(ctx, input), 403, 'grant_revoked');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a replayed assertion through the unique assertion hash', async () => {
    // An authenticator that reports counter 0 never advances, so only the
    // audit's unique assertion hash stops the replay.
    const ctx = await setupOrgKey({ counter: 0 });
    const input = await signInput(ctx, MESSAGE, { counter: 0 });

    await sign(ctx, input);
    await expectRefusal(sign(ctx, input), 403, 'assertion_consumed');
    expect(ctx.state.audits).toHaveLength(1);
  });

  test('rolls back the passkey counter and returns no signature when the audit insert fails', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);
    ctx.fail.auditInsert = true;

    await expect(sign(ctx, input)).rejects.toThrow('injected audit insert failure');

    expect(ctx.state.audits).toHaveLength(0);
    expect(ctx.state.passkeys[0]?.counter).toBe(0);
  });

  test('refuses a raw digest that is not 32 bytes and consumes no counter or audit', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, 'too-short', {}, { format: 'raw' });

    await expectRefusal(sign(ctx, input), 400, 'invalid_raw_digest');

    expect(ctx.state.audits).toHaveLength(0);
    expect(ctx.state.passkeys[0]?.counter).toBe(0);
  });
});
