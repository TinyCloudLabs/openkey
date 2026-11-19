import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { verifyMessage, type Hex } from 'viem';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import {
  canonicalSignatureHash,
  issueOrgKeySignChallenge,
  messageDigestHex,
  OrgKeyRefusal,
  orgKeySignChallenge,
  signOrgKeyMessage,
  type OrgKeySignInput,
} from '../services/org-keys';
import { asPrisma, assertionFor, ORIGIN, RP_ID, setupOrgKey } from './org-keys-fixtures';

const MESSAGE = 'Sign in to the org console, nonce 42';
const KIND = 'test-kind';

type Ctx = Awaited<ReturnType<typeof setupOrgKey>>;

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function parseDer(der: Buffer): { r: bigint; s: bigint } {
  const readInt = (offset: number) => {
    const length = der[offset + 1] ?? 0;
    const value = der.subarray(offset + 2, offset + 2 + length).reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
    return { value, next: offset + 2 + length };
  };
  const r = readInt(2);
  const s = readInt(r.next);
  return { r: r.value, s: s.value };
}

function encodeInt(value: bigint): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let bytes = Buffer.from(hex, 'hex');
  if (bytes[0]! & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
}

// The same ECDSA signature in either s form. Both verify, so an authenticator
// may emit either. The test uses this to build the two variants of one assertion.
function withSForm(assertion: AuthenticationResponseJSON, form: 'low' | 'high'): AuthenticationResponseJSON {
  const { r, s } = parseDer(Buffer.from(assertion.response.signature, 'base64url'));
  const low = s > P256_N - s ? P256_N - s : s;
  const body = Buffer.concat([encodeInt(r), encodeInt(form === 'low' ? low : P256_N - low)]);
  const der = Buffer.concat([Buffer.from([0x30, body.length]), body]);
  return { ...assertion, response: { ...assertion.response, signature: der.toString('base64url') } };
}

async function issue(ctx: Ctx, message: string) {
  return issueOrgKeySignChallenge(asPrisma(ctx.db), {
    userId: 'user_1',
    keyId: ctx.key.keyId,
    grantId: ctx.key.grantId,
    message,
  });
}

// A signing request for MESSAGE with a freshly issued server nonce and a
// passkey assertion over that nonce's challenge.
async function signInput(
  ctx: Ctx,
  message: string,
  assertionOptions: Parameters<typeof assertionFor>[2] = {},
  overrides: Partial<OrgKeySignInput> = {},
): Promise<OrgKeySignInput> {
  const issued = await issue(ctx, message);
  return {
    userId: 'user_1',
    keyId: ctx.key.keyId,
    nonce: issued.nonce,
    origin: ORIGIN,
    message,
    messageKind: KIND,
    assertion: assertionFor(ctx.passkey, issued.challenge, assertionOptions),
    rpID: RP_ID,
    expectedOrigin: ORIGIN,
    ...overrides,
  };
}

function sign(ctx: Ctx, input: OrgKeySignInput) {
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
  test('signs under a fresh passkey and records one audit row with actor, grant, origin, digest, role, and kind', async () => {
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
      role: 'OWNER',
      messageKind: KIND,
    });
    expect(ctx.state.passkeys[0]?.counter).toBe(1);
  });

  test('refuses a malformed assertion before any challenge is consumed', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);
    const malformed = { ...input.assertion, id: undefined } as unknown as OrgKeySignInput['assertion'];

    await expectRefusal(sign(ctx, { ...input, assertion: malformed }), 403, 'passkey_invalid');
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses an empty nonce', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);

    await expectRefusal(sign(ctx, { ...input, nonce: '' }), 403, 'challenge_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a nonce the server never issued', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);

    await expectRefusal(sign(ctx, { ...input, nonce: 'never-issued' }), 403, 'challenge_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a nonce issued for a different message and leaves it unconsumed', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, 'message A');

    await expectRefusal(sign(ctx, { ...input, message: 'message B' }), 403, 'challenge_invalid');
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
    expect(ctx.state.audits).toHaveLength(0);
    expect(ctx.state.passkeys[0]?.counter).toBe(0);
  });

  test('refuses a nonce issued for a different key', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);

    await expectRefusal(sign(ctx, { ...input, keyId: 'other_key' }), 403, 'challenge_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('binds the challenge preimage to the grant, so an assertion over another grant fails', async () => {
    const ctx = await setupOrgKey();
    const issued = await issue(ctx, MESSAGE);
    const overOtherGrant = orgKeySignChallenge({
      keyId: ctx.key.keyId,
      grantId: 'other_grant',
      nonce: issued.nonce,
      messageDigest: messageDigestHex(MESSAGE),
    }).toString('base64url');

    await expectRefusal(
      sign(ctx, {
        ...(await signInput(ctx, MESSAGE)),
        nonce: issued.nonce,
        assertion: assertionFor(ctx.passkey, overOtherGrant),
      }),
      403,
      'passkey_invalid',
    );
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses an expired nonce', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);
    ctx.state.challenges[0] = { ...ctx.state.challenges[0], expiresAt: new Date(Date.now() - 1) };

    await expectRefusal(sign(ctx, input), 403, 'challenge_expired');
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

  test('refuses once the grant is revoked, even with a valid assertion, and leaves the nonce unconsumed', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);
    ctx.state.grants[0] = { ...ctx.state.grants[0], revokedAt: new Date() };

    await expectRefusal(sign(ctx, input), 403, 'grant_revoked');
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a replayed request once its nonce is consumed', async () => {
    const ctx = await setupOrgKey({ counter: 0 });
    const input = await signInput(ctx, MESSAGE, { counter: 0 });

    await sign(ctx, input);
    await expectRefusal(sign(ctx, input), 403, 'challenge_consumed');
    expect(ctx.state.audits).toHaveLength(1);
  });

  test('accepts a high-s signature: the service does not refuse by s form', async () => {
    const ctx = await setupOrgKey({ counter: 0 });
    const issued = await issue(ctx, MESSAGE);
    const base = assertionFor(ctx.passkey, issued.challenge, { counter: 0 });

    const result = await sign(ctx, {
      ...(await signInput(ctx, MESSAGE)),
      nonce: issued.nonce,
      assertion: withSForm(base, 'high'),
    });

    expect(await verifyMessage({ address: ctx.key.address as Hex, message: MESSAGE, signature: result.signature })).toBe(
      true,
    );
    expect(ctx.state.audits).toHaveLength(1);
  });

  test('refuses the low-s twin of a consumed assertion through the canonical hash, even with an unconsumed nonce', async () => {
    const ctx = await setupOrgKey({ counter: 0 });
    const issued = await issue(ctx, MESSAGE);
    const base = assertionFor(ctx.passkey, issued.challenge, { counter: 0 });
    const request = { ...(await signInput(ctx, MESSAGE)), nonce: issued.nonce };

    await sign(ctx, { ...request, assertion: withSForm(base, 'high') });
    // Simulates a challenge row left unconsumed, so only the audit's canonical
    // hash can stop the twin.
    ctx.state.challenges[0] = { ...ctx.state.challenges[0], consumedAt: null };

    await expectRefusal(sign(ctx, { ...request, assertion: withSForm(base, 'low') }), 403, 'assertion_consumed');
    expect(ctx.state.audits).toHaveLength(1);
  });

  test('canonical signature hash is equal for both s forms and differs across signatures', async () => {
    const ctx = await setupOrgKey();
    const issued = await issue(ctx, MESSAGE);
    const first = assertionFor(ctx.passkey, issued.challenge);
    const second = assertionFor(ctx.passkey, issued.challenge, { counter: 2 });

    const low = canonicalSignatureHash(withSForm(first, 'low').response.signature);
    const high = canonicalSignatureHash(withSForm(first, 'high').response.signature);
    expect(high).toBe(low);
    expect(canonicalSignatureHash(second.response.signature)).not.toBe(low);
  });

  test('rolls back the passkey counter and the nonce, and returns no signature, when the audit insert fails', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, MESSAGE);
    ctx.fail.auditInsert = true;

    await expect(sign(ctx, input)).rejects.toThrow('injected audit insert failure');

    expect(ctx.state.audits).toHaveLength(0);
    expect(ctx.state.passkeys[0]?.counter).toBe(0);
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
  });
});
