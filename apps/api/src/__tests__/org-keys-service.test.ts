import './tee-dev-env';
import { afterAll, afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { verifyMessage, type Hex } from 'viem';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import {
  canonicalSignatureHash,
  classifyOrgKeyMessage,
  issueOrgKeySignChallenge,
  loadOrgKeyRecord,
  messageDigestHex,
  OrgKeyRefusal,
  orgKeySignChallenge,
  signOrgKeyMessage,
  type OrgKeySignInput,
} from '../services/org-keys';
import { canonicalJson, ISSUER_STATEMENT_KIND, parseIssuerStatement, renderIssuerStatement } from '../services/org-issuer-statement';
import { adminAccountFor, renderOrgSpaceMessage, spaceIdFor } from '../services/org-space-signing';
import { addEd25519Passkey, addRs256Passkey, asPrisma, assertionFor, CANONICAL_ADMIN_ADDRESS, ISSUER_DID, ORG_ID, ORIGIN, RP_ID, setupOrgKey, SLUG } from './org-keys-fixtures';

type Ctx = Awaited<ReturnType<typeof setupOrgKey>>;

// An Ed25519 did:key: the space-host recipient the node stages for the org space.
const DID_KEY = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';

// A kind 2 (org-space) message the classifier accepts for this org key: space-host on
// the key's own space, from the credentials.org origin.
function orgSpaceMessageFor(ctx: Ctx): string {
  const space = spaceIdFor(ctx.key.address);
  const now = Date.now();
  return renderOrgSpaceMessage({
    domain: new URL(ORIGIN).host,
    address: ctx.key.address,
    uri: DID_KEY,
    nonce: 'abcdefgh12',
    issuedAt: new Date(now).toISOString(),
    expirationTime: new Date(now + 60 * 60 * 1000).toISOString(),
    att: [
      { resource: `${space}/space`, ability: 'tinycloud.space/host' },
      { resource: `${space}/sql/shared-index`, ability: 'tinycloud.sql/admin' },
    ],
    fact: { adminAccount: adminAccountFor(CANONICAL_ADMIN_ADDRESS), class: 'space-host', grantId: ctx.key.grantId },
  });
}

// Canonical authorize statement for this org key. The controller comes from the
// key that setupOrgKey generated (a fresh key per call), so it is read from ctx.
// `overrides` varies one field, for tests that need two distinct statements.
function statementFor(ctx: Ctx, overrides: Record<string, unknown> = {}): string {
  return canonicalJson({
    action: 'authorize',
    alg: 'EdDSA',
    audience: ORIGIN,
    controller: ctx.key.controllerDid,
    issuerDid: ISSUER_DID,
    kid: `${ISSUER_DID}#issuing-1`,
    nonce: '00112233445566778899aabbccddeeff',
    notBefore: '2026-10-20T09:00:00Z',
    orgId: ORG_ID,
    profiles: ['tinycloud.org-membership/v1'],
    publicKey: 'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI',
    seq: 1,
    slug: SLUG,
    type: 'tinycloud.org-issuer-authorization/v1',
    vcts: ['opencredentials.org-membership/v1', 'tinycloud.org-badge/v1'],
    ...overrides,
  });
}

// The text the org key signs (EIP-191). The server renders it from the same canonical input.
function signedTextFor(message: string): string {
  return renderIssuerStatement(parseIssuerStatement(message, [ORIGIN]), message);
}

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
    role: 'OWNER',
    origin: ORIGIN,
    message,
  });
}

// A signing request for `message` with a freshly issued server nonce and a
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
  // The statement kill switch (K4 D1) is default OFF. Each test enables it; the
  // default-off test below turns it off explicitly.
  const originalStatementFlag = process.env.ORG_ISSUER_STATEMENT_ENABLED;
  beforeEach(() => {
    process.env.ORG_ISSUER_STATEMENT_ENABLED = 'true';
  });
  afterAll(() => {
    if (originalStatementFlag === undefined) delete process.env.ORG_ISSUER_STATEMENT_ENABLED;
    else process.env.ORG_ISSUER_STATEMENT_ENABLED = originalStatementFlag;
  });

  test('refuses statement signing while ORG_ISSUER_STATEMENT_ENABLED is off, and stores no challenge', async () => {
    process.env.ORG_ISSUER_STATEMENT_ENABLED = 'false';
    const ctx = await setupOrgKey();
    await expectRefusal(issue(ctx, statementFor(ctx)), 403, 'unsupported_message_kind');
    expect(ctx.state.challenges).toHaveLength(0);
  });

  describe('org-space signing flag', () => {
    const originalOrgSpaceFlag = process.env.ORG_SPACE_SIGNING_ENABLED;
    afterEach(() => {
      if (originalOrgSpaceFlag === undefined) delete process.env.ORG_SPACE_SIGNING_ENABLED;
      else process.env.ORG_SPACE_SIGNING_ENABLED = originalOrgSpaceFlag;
    });

    // Runs the classifier gate on the key's stored record. The fake Prisma client ignores
    // the `key` relation select, so the key address is added the way real Prisma returns it.
    async function classifyFor(
      ctx: Ctx,
      message: string,
      { origin = ORIGIN, withGrant = true, withKey = true }: { origin?: string; withGrant?: boolean; withKey?: boolean } = {},
    ) {
      const row = await loadOrgKeyRecord(asPrisma(ctx.db), ctx.key.keyId);
      if (!row) throw new Error('org key record missing from fixture');
      return classifyOrgKeyMessage(message, {
        record: withKey ? { ...row, key: { address: ctx.key.address } } : row,
        requestingOrigin: origin,
        ...(withGrant ? { grant: { grantId: ctx.key.grantId, role: 'OWNER' as const, adminAddress: CANONICAL_ADMIN_ADDRESS } } : {}),
      });
    }

    test('refuses an org-space message while ORG_SPACE_SIGNING_ENABLED is off', async () => {
      process.env.ORG_SPACE_SIGNING_ENABLED = 'false';
      const ctx = await setupOrgKey();
      expect(await classifyFor(ctx, orgSpaceMessageFor(ctx))).toEqual({ ok: false, refusal: 'unsupported_message_kind' });
    });

    test('accepts the same org-space message once ORG_SPACE_SIGNING_ENABLED is on', async () => {
      process.env.ORG_SPACE_SIGNING_ENABLED = 'true';
      const ctx = await setupOrgKey();
      expect(await classifyFor(ctx, orgSpaceMessageFor(ctx))).toMatchObject({ ok: true, kind: 'org-space/space-host' });
    });

    test('refuses an org-space message with no active grant while the flag is on', async () => {
      process.env.ORG_SPACE_SIGNING_ENABLED = 'true';
      const ctx = await setupOrgKey();
      expect(await classifyFor(ctx, orgSpaceMessageFor(ctx), { withGrant: false })).toEqual({
        ok: false,
        refusal: 'unsupported_message_kind',
      });
    });

    test('refuses an org-space message when the org key record carries no key address while the flag is on', async () => {
      process.env.ORG_SPACE_SIGNING_ENABLED = 'true';
      const ctx = await setupOrgKey();
      expect(await classifyFor(ctx, orgSpaceMessageFor(ctx), { withKey: false })).toEqual({
        ok: false,
        refusal: 'unsupported_message_kind',
      });
    });

    test('returns the org-space refusal for an origin outside the allowlist, instead of accepting the message', async () => {
      process.env.ORG_SPACE_SIGNING_ENABLED = 'true';
      const ctx = await setupOrgKey();
      expect(await classifyFor(ctx, orgSpaceMessageFor(ctx), { origin: 'https://evil.example' })).toMatchObject({
        ok: false,
        refusal: 'org_space_origin_mismatch',
      });
    });
  });

  test('refuses account-binding bytes even when the message also names the statement, and stores no challenge', async () => {
    const ctx = await setupOrgKey();
    await expectRefusal(issue(ctx, `${statementFor(ctx)}\naccount-binding/v1`), 403, 'binding_bytes_refused');
    expect(ctx.state.challenges).toHaveLength(0);
  });

  test.each(['toString', 'constructor', '__proto__'])(
    'refuses the prototype-named action %s as unknown_action, and stores no challenge',
    async (action) => {
      const ctx = await setupOrgKey();
      await expectRefusal(issue(ctx, statementFor(ctx, { action })), 403, 'unknown_action');
      expect(ctx.state.challenges).toHaveLength(0);
    },
  );

  test('refuses org-binding bytes, and stores no challenge', async () => {
    const ctx = await setupOrgKey();
    await expectRefusal(issue(ctx, 'org-binding/v1 bound to another org'), 403, 'binding_bytes_refused');
    expect(ctx.state.challenges).toHaveLength(0);
  });

  test('refuses a SIWE that carries a tinycloud.credentials capability, and stores no challenge', async () => {
    const ctx = await setupOrgKey();
    const siwe = [
      'example.com wants you to sign in with your Ethereum account:',
      '0x0000000000000000000000000000000000000001',
      '',
      'URI: https://example.com',
      'Resources:',
      '- tinycloud.credentials/present',
    ].join('\n');
    await expectRefusal(issue(ctx, siwe), 403, 'credentials_capability_refused');
    expect(ctx.state.challenges).toHaveLength(0);
  });

  test('signs under a fresh passkey and records one audit row with actor, grant, origin, digest, role, and kind', async () => {
    const ctx = await setupOrgKey();
    const message = statementFor(ctx);
    const result = await sign(ctx, await signInput(ctx, message));

    expect(result.address).toBe(ctx.key.address);
    expect(
      await verifyMessage({ address: ctx.key.address as Hex, message: signedTextFor(message), signature: result.signature }),
    ).toBe(true);

    expect(ctx.state.audits).toHaveLength(1);
    expect(ctx.state.audits[0]).toMatchObject({
      keyId: ctx.key.keyId,
      grantId: ctx.key.grantId,
      actorUserId: 'user_1',
      origin: ORIGIN,
      messageDigest: createHash('sha256').update(message, 'utf8').digest('hex'),
      role: 'OWNER',
      messageKind: ISSUER_STATEMENT_KIND,
    });
    const challengeId = ctx.state.challenges[0]?.id;
    expect(challengeId).toEqual(expect.any(String));
    expect(ctx.state.audits[0]?.challengeId).toBe(challengeId);
    expect(ctx.state.passkeys[0]?.counter).toBe(1);
  });

  test('signs under an RS256 passkey: Better Auth registers RS256 alongside ES256, and the signature is not refused as passkey_invalid', async () => {
    const base = await setupOrgKey();
    const rs256 = addRs256Passkey(base.state, 'user_1');
    const ctx: Ctx = { ...base, passkey: rs256 };
    const message = statementFor(ctx);
    const result = await sign(ctx, await signInput(ctx, message));

    expect(
      await verifyMessage({ address: ctx.key.address as Hex, message: signedTextFor(message), signature: result.signature }),
    ).toBe(true);
    expect(ctx.state.audits).toHaveLength(1);
    expect(ctx.state.passkeys.find((row) => row.credentialID === rs256.credentialID)?.counter).toBe(1);
  });

  test('signs under an Ed25519 (EdDSA) passkey through the raw-signature path, without a SHA-256 pre-hash', async () => {
    const base = await setupOrgKey();
    const ed = addEd25519Passkey(base.state, 'user_1');
    const ctx: Ctx = { ...base, passkey: ed };
    const message = statementFor(ctx);
    const result = await sign(ctx, await signInput(ctx, message));

    expect(
      await verifyMessage({ address: ctx.key.address as Hex, message: signedTextFor(message), signature: result.signature }),
    ).toBe(true);
    expect(ctx.state.audits).toHaveLength(1);
    expect(ctx.state.passkeys.find((row) => row.credentialID === ed.credentialID)?.counter).toBe(1);
  });

  test('refuses a malformed assertion before any challenge is consumed', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));
    const malformed = { ...input.assertion, id: undefined } as unknown as OrgKeySignInput['assertion'];

    await expectRefusal(sign(ctx, { ...input, assertion: malformed }), 403, 'passkey_invalid');
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a DER signature whose outer tag is not SEQUENCE, even when its integers are valid', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));
    const der = Buffer.from(input.assertion.response.signature, 'base64url');
    expect(der[0]).toBe(0x30);
    const wrongTag = Buffer.from(der);
    wrongTag[0] = 0x31;
    const assertion = { ...input.assertion, response: { ...input.assertion.response, signature: wrongTag.toString('base64url') } };

    await expectRefusal(sign(ctx, { ...input, assertion }), 403, 'passkey_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('canonicalSignatureHash refuses a DER blob whose outer tag is not SEQUENCE, and accepts the same blob with the tag fixed', () => {
    // SEQUENCE { INTEGER 1, INTEGER 1 }. The two blobs differ only in the outer tag byte.
    const body = [0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    const good = Buffer.from([0x30, body.length, ...body]).toString('base64url');
    const wrongTag = Buffer.from([0x31, body.length, ...body]).toString('base64url');

    expect(() => canonicalSignatureHash(good, true)).not.toThrow();
    let caught: unknown;
    try {
      canonicalSignatureHash(wrongTag, true);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(OrgKeyRefusal);
    expect(caught).toMatchObject({ status: 403, code: 'passkey_invalid' });
  });

  test('refuses an empty nonce', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));

    await expectRefusal(sign(ctx, { ...input, nonce: '' }), 403, 'challenge_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a nonce the server never issued', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));

    await expectRefusal(sign(ctx, { ...input, nonce: 'never-issued' }), 403, 'challenge_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a nonce issued for a different message and leaves it unconsumed', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx, { seq: 1 }));

    await expectRefusal(sign(ctx, { ...input, message: statementFor(ctx, { seq: 2 }) }), 403, 'challenge_invalid');
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
    expect(ctx.state.audits).toHaveLength(0);
    expect(ctx.state.passkeys[0]?.counter).toBe(0);
  });

  test('refuses a nonce issued for a different key', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));

    await expectRefusal(sign(ctx, { ...input, keyId: 'other_key' }), 403, 'challenge_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('binds the challenge preimage to the grant, so an assertion over another grant fails', async () => {
    const ctx = await setupOrgKey();
    const message = statementFor(ctx);
    const issued = await issue(ctx, message);
    const overOtherGrant = orgKeySignChallenge({
      keyId: ctx.key.keyId,
      grantId: 'other_grant',
      nonce: issued.nonce,
      messageDigest: messageDigestHex(message),
      origin: ORIGIN,
    }).toString('base64url');

    await expectRefusal(
      sign(ctx, {
        ...(await signInput(ctx, message)),
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
    const input = await signInput(ctx, statementFor(ctx));
    ctx.state.challenges[0] = { ...ctx.state.challenges[0], expiresAt: new Date(Date.now() - 1) };

    await expectRefusal(sign(ctx, input), 403, 'challenge_expired');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses an assertion for a different origin', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx), { origin: 'https://evil.example' });

    await expectRefusal(sign(ctx, input), 403, 'passkey_invalid');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a user-verification-free assertion', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx), { userVerified: false });

    await expectRefusal(sign(ctx, input), 403, 'passkey_invalid');
  });

  test('refuses a signature counter that does not advance', async () => {
    const ctx = await setupOrgKey({ counter: 5 });
    const input = await signInput(ctx, statementFor(ctx), { counter: 1 });

    await expectRefusal(sign(ctx, input), 403, 'passkey_invalid');
    expect(ctx.state.passkeys[0]?.counter).toBe(5);
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a passkey that belongs to another user', async () => {
    const ctx = await setupOrgKey();
    ctx.state.passkeys[0] = { ...ctx.state.passkeys[0], userId: 'user_2' };

    await expectRefusal(sign(ctx, await signInput(ctx, statementFor(ctx))), 403, 'passkey_required');
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses once the grant is revoked, even with a valid assertion, and leaves the nonce unconsumed', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));
    ctx.state.grants[0] = { ...ctx.state.grants[0], revokedAt: new Date() };

    await expectRefusal(sign(ctx, input), 403, 'grant_revoked');
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses a sign attempt when the grant was replaced after the challenge was issued, and leaves the nonce unconsumed', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));
    ctx.state.grants[0] = { ...ctx.state.grants[0], revokedAt: new Date() };
    ctx.state.grants.push({ ...ctx.state.grants[0], id: 'grant_replacement', revokedAt: null });

    await expectRefusal(sign(ctx, input), 403, 'grant_revoked');
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('reports a stale grant as grant_revoked before it checks the passkey, so an unregistered credential does not change the refusal', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));
    ctx.state.grants[0] = { ...ctx.state.grants[0], revokedAt: new Date() };
    ctx.state.grants.push({ ...ctx.state.grants[0], id: 'grant_replacement', revokedAt: null });

    await expectRefusal(sign(ctx, { ...input, assertion: { ...input.assertion, id: 'unregistered_credential' } }), 403, 'grant_revoked');
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
  });

  test('refuses a replayed request once its nonce is consumed', async () => {
    const ctx = await setupOrgKey({ counter: 0 });
    const input = await signInput(ctx, statementFor(ctx), { counter: 0 });

    await sign(ctx, input);
    await expectRefusal(sign(ctx, input), 403, 'challenge_consumed');
    expect(ctx.state.audits).toHaveLength(1);
  });

  test('refuses when the grant is revoked between the active-grant read and the signing lock, and leaves the nonce unconsumed', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));
    // The FOR SHARE lock read sees no active row: a revoke landed after the active-grant read.
    Object.assign(ctx.db, { $queryRaw: async () => [] });

    await expectRefusal(sign(ctx, input), 403, 'grant_revoked');
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('refuses an org-space message when the grant is downgraded to ADMIN between the active-grant read and the signing lock', async () => {
    const originalFlag = process.env.ORG_SPACE_SIGNING_ENABLED;
    process.env.ORG_SPACE_SIGNING_ENABLED = 'true';
    try {
      const ctx = await setupOrgKey();
      // The fake client drops the `key` relation (see classifyFor), so the record gets its key here.
      const orgKey = ctx.db.orgKey as {
        findUnique: (args: unknown) => Promise<Record<string, unknown> | null>;
      };
      const findRecord = orgKey.findUnique;
      orgKey.findUnique = async (args) => {
        const row = await findRecord(args);
        return row ? { ...row, key: { address: ctx.key.address } } : row;
      };
      const input = await signInput(ctx, orgSpaceMessageFor(ctx));
      // Space-host requires OWNER. The lock read sees the grant downgraded to ADMIN.
      Object.assign(ctx.db, { $queryRaw: async () => [{ id: ctx.key.grantId, role: 'ADMIN' }] });

      await expectRefusal(sign(ctx, input), 403, 'org_space_role_insufficient');
      expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
      expect(ctx.state.audits).toHaveLength(0);
    } finally {
      if (originalFlag === undefined) delete process.env.ORG_SPACE_SIGNING_ENABLED;
      else process.env.ORG_SPACE_SIGNING_ENABLED = originalFlag;
    }
  });

  test('accepts a high-s signature: the service does not refuse by s form', async () => {
    const ctx = await setupOrgKey({ counter: 0 });
    const message = statementFor(ctx);
    const issued = await issue(ctx, message);
    const base = assertionFor(ctx.passkey, issued.challenge, { counter: 0 });

    const result = await sign(ctx, {
      ...(await signInput(ctx, message)),
      nonce: issued.nonce,
      assertion: withSForm(base, 'high'),
    });

    expect(
      await verifyMessage({ address: ctx.key.address as Hex, message: signedTextFor(message), signature: result.signature }),
    ).toBe(true);
    expect(ctx.state.audits).toHaveLength(1);
  });

  test('refuses the low-s twin of a consumed assertion through the canonical hash, even with an unconsumed nonce', async () => {
    const ctx = await setupOrgKey({ counter: 0 });
    const message = statementFor(ctx);
    const issued = await issue(ctx, message);
    const base = assertionFor(ctx.passkey, issued.challenge, { counter: 0 });
    const request = { ...(await signInput(ctx, message)), nonce: issued.nonce };

    await sign(ctx, { ...request, assertion: withSForm(base, 'high') });
    // Simulates a challenge row left unconsumed, so only the audit's canonical
    // hash can stop the twin.
    ctx.state.challenges[0] = { ...ctx.state.challenges[0], consumedAt: null };

    await expectRefusal(sign(ctx, { ...request, assertion: withSForm(base, 'low') }), 403, 'assertion_consumed');
    expect(ctx.state.audits).toHaveLength(1);
  });

  test('canonical signature hash is equal for both s forms and differs across signatures', async () => {
    const ctx = await setupOrgKey();
    const issued = await issue(ctx, statementFor(ctx));
    const first = assertionFor(ctx.passkey, issued.challenge);
    const second = assertionFor(ctx.passkey, issued.challenge, { counter: 2 });

    const low = canonicalSignatureHash(withSForm(first, 'low').response.signature, true);
    const high = canonicalSignatureHash(withSForm(first, 'high').response.signature, true);
    expect(high).toBe(low);
    expect(canonicalSignatureHash(second.response.signature, true)).not.toBe(low);
  });

  test('rolls back the passkey counter and the nonce, and returns no signature, when the audit insert fails', async () => {
    const ctx = await setupOrgKey();
    const input = await signInput(ctx, statementFor(ctx));
    ctx.fail.auditInsert = true;

    await expect(sign(ctx, input)).rejects.toThrow('injected audit insert failure');

    expect(ctx.state.audits).toHaveLength(0);
    expect(ctx.state.passkeys[0]?.counter).toBe(0);
    expect(ctx.state.challenges[0]?.consumedAt).toBeNull();
  });
});
