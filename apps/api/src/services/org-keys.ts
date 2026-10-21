import { createHash, randomBytes } from 'node:crypto';
import { getAddress, type Hex } from 'viem';
import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from '@simplewebauthn/server';
import { cose, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import type { Prisma, PrismaClient } from '@openkey/db';
import {
  createWalletFromPrivateKey,
  generatePrivateKey,
  getAddressFromPrivateKey,
  seal,
  unseal,
  type TeeClient,
} from '@openkey/tee';
import { createSealingContext, deriveKeyForRecord } from './key-sealing';
import { checkHandle, classifyIssuerStatement, ISSUER_STATEMENT_KIND, IssuerStatementRefusal, issuerDidForOrgId, namesIssuerStatement, type IssuerStatementRecord } from './org-issuer-statement';
import { classifyOrgSpaceMessage, isOrgSpaceSigningEnabled, namesOrgSpaceMessage, roleSatisfies, type OrgRole } from './org-space-signing';

// Capability flag for organization key custody (TC-1518). Default off: the
// org-key routes answer 404 until the flag is set to "true".
export const ORG_KEY_CUSTODY_FLAG = 'ORG_KEY_CUSTODY_ENABLED';

export function isOrgKeyCustodyEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env[ORG_KEY_CUSTODY_FLAG] === 'true';
}

// K4 kill switch for issuer-statement signing (kind 1). Separate from the custody flag so
// statement signing can be disabled while the org-key routes stay up. Default off: a
// statement is refused as an unsupported message kind.
export const ORG_ISSUER_STATEMENT_FLAG = 'ORG_ISSUER_STATEMENT_ENABLED';

export function isIssuerStatementSigningEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env[ORG_ISSUER_STATEMENT_FLAG] === 'true';
}

// K1 D4.1: origins from which an org-key signing request may originate.
export const ORG_KEY_ORIGIN = 'https://credentials.org';
export const ORG_KEY_ORIGINS: readonly string[] = [ORG_KEY_ORIGIN];

// Domain separator for the fresh-passkey challenge (K1 D4.5).
export const ORG_KEY_SIGN_DOMAIN = 'openkey.org-key-sign/v1';

// How long an issued signing challenge may be used (K2a F2).
export const ORG_KEY_CHALLENGE_TTL_MS = 5 * 60 * 1000;

// This module is the only place that reads custody = ORG rows. Personal paths
// reach ORG rows through no query (ORG rows have userId NULL; see
// personalKeyWhere in primary-key.ts).
function activeOrgGrantWhere(userId: string) {
  return {
    granteeUserId: userId,
    revokedAt: null,
    key: {
      custody: 'ORG' as const,
      archivedAt: null,
      orgKey: { isNot: null },
    },
  };
}

export type OrgKeyPickerItem = {
  keyId: string;
  address: string;
  label: string | null;
  orgName: string;
  role: 'OWNER' | 'ADMIN';
  usage: 'org-controller';
  badge: { kind: 'org'; text: string };
};

function toPickerItem(grant: {
  role: 'OWNER' | 'ADMIN';
  key: { id: string; address: string; label: string | null; orgKey: { orgName: string } | null };
}): OrgKeyPickerItem {
  const orgName = grant.key.orgKey?.orgName ?? '';
  return {
    keyId: grant.key.id,
    address: grant.key.address,
    label: grant.key.label,
    orgName,
    role: grant.role,
    usage: 'org-controller',
    badge: { kind: 'org', text: `Org key · ${orgName}` },
  };
}

const grantSelect = {
  role: true,
  key: { select: { id: true, address: true, label: true, orgKey: { select: { orgName: true } } } },
} as const;

export async function listOrgKeysForUser(prisma: PrismaClient, userId: string): Promise<OrgKeyPickerItem[]> {
  const grants = await prisma.keyGrant.findMany({
    where: activeOrgGrantWhere(userId),
    select: grantSelect,
    orderBy: { createdAt: 'asc' },
  });
  return grants.map(toPickerItem);
}

export async function findOrgKeyForUser(
  prisma: PrismaClient,
  userId: string,
  keyId: string,
): Promise<OrgKeyPickerItem | null> {
  const grant = await prisma.keyGrant.findFirst({
    where: { keyId, ...activeOrgGrantWhere(userId) },
    select: grantSelect,
  });
  return grant ? toPickerItem(grant) : null;
}

// The active grant the caller signs under. Null means the caller has no
// active grant on this key (K1 D4.1: 403 before anything else is checked).
export async function findActiveOrgGrant(
  prisma: PrismaClient,
  userId: string,
  keyId: string,
): Promise<{ grantId: string; role: 'OWNER' | 'ADMIN' } | null> {
  const grant = await prisma.keyGrant.findFirst({
    where: { keyId, ...activeOrgGrantWhere(userId) },
    select: { id: true, role: true },
  });
  return grant ? { grantId: grant.id, role: grant.role } : null;
}

export class OrgKeyRefusal extends Error {
  constructor(
    readonly status: 400 | 403 | 404,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export type CreateOrgKeyInput = {
  userId: string;
  orgId: string;
  orgName: string;
  slug: string;
  label?: string | null;
};

// The controller of an org key is the did:pkh of the key's own address on chain 1,
// the same form managed keys use in routes/delegate.ts. Clients never choose it.
export function controllerDidForAddress(address: string): string {
  return `did:pkh:eip155:1:${getAddress(address)}`;
}

// Validates org identity before any key material is generated (T1 D1, D2). The issuer DID is
// derived from the OrgId; a caller-supplied issuerDid is never trusted.
function deriveOrgIdentity(orgId: string, slug: string): string {
  try {
    checkHandle(slug, 'slug');
    return issuerDidForOrgId(orgId);
  } catch (error) {
    if (error instanceof IssuerStatementRefusal) throw new OrgKeyRefusal(400, error.code, error.message);
    throw error;
  }
}

// Creates an ORG-custodied key with the caller as its OWNER (K1 D2). The key has
// no personal owner (userId NULL), a per-key sealing context, and is never the
// canonical TinyCloud key.
export async function createOrgKey(prisma: PrismaClient, tee: TeeClient, input: CreateOrgKeyInput) {
  const issuerDid = deriveOrgIdentity(input.orgId, input.slug);
  const privateKey = generatePrivateKey();
  const address = getAddressFromPrivateKey(privateKey);
  const controllerDid = controllerDidForAddress(address);
  const sealingContext = createSealingContext();
  const sealedBlob = await seal(privateKey, await deriveKeyForRecord(tee, { userId: null, sealingContext }));

  return prisma.$transaction(async (tx) => {
    const key = await tx.ethereumKey.create({
      data: {
        userId: null,
        custody: 'ORG',
        keyType: 'MANAGED',
        address,
        publicKey: address,
        sealedBlob,
        sealingContext,
        isCanonicalTinyCloud: false,
        label: input.label ?? input.orgName,
      },
      select: { id: true, address: true, label: true },
    });
    await tx.orgKey.create({
      data: {
        keyId: key.id,
        orgId: input.orgId,
        orgName: input.orgName,
        slug: input.slug,
        issuerDid,
        controllerDid,
      },
    });
    const grant = await tx.keyGrant.create({
      data: {
        keyId: key.id,
        role: 'OWNER',
        granteeUserId: input.userId,
        invitedByUserId: input.userId,
        acceptedAt: new Date(),
      },
      select: { id: true },
    });
    return { keyId: key.id, grantId: grant.id, address: key.address, label: key.label, controllerDid };
  });
}

export type OrgKeyMessageClassification =
  | { ok: true; kind: string; action: string; text: string; role?: OrgRole }
  | { ok: false; refusal: string };

// Kind 2 signing context: the grant the signer holds on this key, matched against the challenge.
export type OrgKeyGrantContext = { grantId: string; role: OrgRole };

// K1 D7 refusals run first and are unconditional. Then the D3 allowlist: kind 1 (the issuer
// statement, while the K4 kill switch is on) and kind 2 (the org-space message, while
// ORG_SPACE_SIGNING_ENABLED is on). Every other message is refused as unsupported.
export function classifyOrgKeyMessage(
  message: string,
  context: {
    record: IssuerStatementRecord & { key?: { address: string } };
    requestingOrigin: string;
    env?: Record<string, string | undefined>;
    grant?: OrgKeyGrantContext;
  },
): OrgKeyMessageClassification {
  if (message.includes('account-binding/v1') || message.includes('org-binding/v1')) {
    return { ok: false, refusal: 'binding_bytes_refused' };
  }
  if (message.includes('tinycloud.credentials/')) {
    return { ok: false, refusal: 'credentials_capability_refused' };
  }
  if (namesOrgSpaceMessage(message)) {
    if (!isOrgSpaceSigningEnabled(context.env) || !context.grant || !context.record.key) {
      return { ok: false, refusal: 'unsupported_message_kind' };
    }
    const org = classifyOrgSpaceMessage(message, {
      allowedOrigins: ORG_KEY_ORIGINS,
      requestingOrigin: context.requestingOrigin,
      address: getAddress(context.record.key.address),
      grantId: context.grant.grantId,
      role: context.grant.role,
    });
    if (!org.ok) return { ok: false, refusal: org.refusal };
    return { ok: true, kind: org.kind, action: org.action, text: org.text, role: org.role };
  }
  if (!namesIssuerStatement(message) || !isIssuerStatementSigningEnabled(context.env)) {
    return { ok: false, refusal: 'unsupported_message_kind' };
  }
  const result = classifyIssuerStatement(message, {
    record: context.record,
    requestingOrigin: context.requestingOrigin,
    allowedAudiences: ORG_KEY_ORIGINS,
  });
  if (!result.ok) return { ok: false, refusal: result.refusal };
  return { ok: true, kind: ISSUER_STATEMENT_KIND, action: result.action, text: result.text };
}

export function messageDigestHex(message: string): string {
  return createHash('sha256').update(message, 'utf8').digest('hex');
}

// The fresh-passkey challenge (K1 D4.5, K2a F2): sha256 over the domain and the
// parts, each part prefixed by its u32be byte length so no two inputs share a
// preimage. The requesting origin is one of the parts, so the passkey signature
// commits to the origin the consent screen showed. The nonce is server-generated
// and single-use (see issueOrgKeySignChallenge).
export function orgKeySignChallenge(parts: {
  keyId: string;
  grantId: string;
  nonce: string;
  messageDigest: string;
  origin: string;
}): Buffer {
  const hash = createHash('sha256');
  for (const part of [ORG_KEY_SIGN_DOMAIN, parts.keyId, parts.grantId, parts.nonce, parts.messageDigest, parts.origin]) {
    const bytes = Buffer.from(part, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest();
}

// The stored record a statement is bound to. Null when the key does not exist.
export async function loadOrgKeyRecord(
  prisma: PrismaClient,
  keyId: string,
): Promise<(IssuerStatementRecord & { key: { address: string } }) | null> {
  return prisma.orgKey.findUnique({
    where: { keyId },
    select: { orgId: true, slug: true, issuerDid: true, controllerDid: true, key: { select: { address: true } } },
  });
}

// Records a server nonce for one signing request. The stored row is the only
// source of keyId, grantId, message digest, and origin at signing time. The message
// is classified here, so a refused message never receives a challenge.
export async function issueOrgKeySignChallenge(
  prisma: PrismaClient,
  input: { userId: string; keyId: string; grantId: string; role: OrgRole; message: string; origin: string },
): Promise<{ nonce: string; challenge: string; expiresAt: Date; kind: string; text: string }> {
  const record = await loadOrgKeyRecord(prisma, input.keyId);
  if (!record) throw new OrgKeyRefusal(404, 'key_not_found', 'Key not found');
  const classification = classifyOrgKeyMessage(input.message, {
    record,
    requestingOrigin: input.origin,
    grant: { grantId: input.grantId, role: input.role },
  });
  if (!classification.ok) throw new OrgKeyRefusal(403, classification.refusal, 'Message is not signable by this key');

  // Expired challenges can never be used. Dropping them keeps the table bounded.
  await prisma.orgKeySignChallenge.deleteMany({ where: { expiresAt: { lt: new Date() } } });

  const nonce = randomBytes(32).toString('base64url');
  const messageDigest = messageDigestHex(input.message);
  const expiresAt = new Date(Date.now() + ORG_KEY_CHALLENGE_TTL_MS);
  await prisma.orgKeySignChallenge.create({
    data: {
      userId: input.userId,
      keyId: input.keyId,
      grantId: input.grantId,
      origin: input.origin,
      nonce,
      messageDigest,
      expiresAt,
    },
  });
  const challenge = orgKeySignChallenge({
    keyId: input.keyId,
    grantId: input.grantId,
    nonce,
    messageDigest,
    origin: input.origin,
  });
  return {
    nonce,
    challenge: challenge.toString('base64url'),
    expiresAt,
    kind: classification.kind,
    text: classification.text,
  };
}

export type OrgKeySignInput = {
  userId: string;
  keyId: string;
  nonce: string;
  origin: string;
  message: string;
  assertion: AuthenticationResponseJSON;
  rpID: string;
  expectedOrigin: string;
};

// P-256 group order. Passkey (WebAuthn ES256) signatures are over P-256, not secp256k1.
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function malformedSignature(): OrgKeyRefusal {
  return new OrgKeyRefusal(403, 'passkey_invalid', 'Passkey signature is not DER-encoded');
}

// Reads one DER INTEGER at offset. Short-form lengths only: an ECDSA component
// is at most 33 bytes, so the long form never occurs.
function readDerInteger(der: Buffer, offset: number): { value: bigint; next: number } {
  if (der[offset] !== 0x02) throw malformedSignature();
  const length = der[offset + 1];
  if (length === undefined || length > 0x7f) throw malformedSignature();
  const start = offset + 2;
  const end = start + length;
  if (end > der.length) throw malformedSignature();
  const value = der.subarray(start, end).reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
  return { value, next: end };
}

function parseDerSignature(der: Buffer): { r: bigint; s: bigint } {
  if (der[0] !== 0x30 || der[1] === undefined || der[1] > 0x7f || der[1] !== der.length - 2) {
    throw malformedSignature();
  }
  const r = readDerInteger(der, 2);
  const s = readDerInteger(der, r.next);
  if (s.next !== der.length) throw malformedSignature();
  return { r: r.value, s: s.value };
}

function to32Bytes(value: bigint): Buffer {
  const hex = value.toString(16).padStart(64, '0');
  if (hex.length > 64) throw malformedSignature();
  return Buffer.from(hex, 'hex');
}

// Both (r, s) and (r, n - s) verify under ECDSA, and authenticators are not
// required to emit low-s. For ES256 the hash covers the canonical form (r, min(s, n - s)),
// so both variants share one audit hash and the unique index blocks the second one.
// Other algorithms hash the raw signature bytes. RSA PKCS#1 v1.5 is deterministic, so the
// bytes identify one assertion. EdDSA uniqueness depends on the verifier rejecting non-canonical S.
// The branch follows the stored COSE algorithm, not the signature shape.
export function canonicalSignatureHash(signatureBase64url: string, es256: boolean): string {
  const signature = Buffer.from(signatureBase64url, 'base64url');
  if (!es256) return createHash('sha256').update(signature).digest('hex');
  const { r, s } = parseDerSignature(signature);
  const canonicalS = s > P256_ORDER - s ? P256_ORDER - s : s;
  return createHash('sha256').update(Buffer.concat([to32Bytes(r), to32Bytes(canonicalS)])).digest('hex');
}

// The COSE algorithm the stored passkey verifies with.
export function passkeyUsesEs256(publicKeyBase64: string): boolean {
  try {
    return decodeCredentialPublicKey(Buffer.from(publicKeyBase64, 'base64')).get(cose.COSEKEYS.alg) === cose.COSEALG.ES256;
  } catch {
    throw new OrgKeyRefusal(403, 'passkey_invalid', 'Passkey public key cannot be decoded');
  }
}

// F3: lock the grant row FOR SHARE. A concurrent revoke takes a conflicting
// row lock, so it waits for this transaction to commit, or this read sees
// the revoke and refuses. Revocation must not interleave with a signature.
// Exported so the lock can be exercised on real Postgres (F-C).
export async function lockActiveGrant(
  tx: Prisma.TransactionClient,
  input: { grantId: string; keyId: string; userId: string },
): Promise<{ id: string; role: 'OWNER' | 'ADMIN' } | null> {
  const [grant] = await tx.$queryRaw<{ id: string; role: 'OWNER' | 'ADMIN' }[]>`
    SELECT id, role FROM "key_grants"
    WHERE id = ${input.grantId} AND "keyId" = ${input.keyId}
      AND "granteeUserId" = ${input.userId} AND "revokedAt" IS NULL
    FOR SHARE`;
  return grant ?? null;
}

// Verifies the fresh passkey and the server challenge, consumes the challenge,
// then writes the audit row and produces the signature in one transaction
// (K1 D4.6). If the audit insert fails, the transaction rolls back and the
// challenge stays unconsumed. A passkey assertion is consumed once: its
// canonical signature hash is unique on the audit table.
export async function signOrgKeyMessage(
  prisma: PrismaClient,
  tee: TeeClient,
  input: OrgKeySignInput,
): Promise<{ signature: Hex; address: string }> {
  // Prisma drops an undefined filter, so a missing nonce or assertion id would
  // match any row of the user. Refuse malformed input before any lookup.
  if (typeof input.nonce !== 'string' || input.nonce.length === 0) {
    throw new OrgKeyRefusal(403, 'challenge_invalid', 'Signing challenge does not match this request');
  }
  if (typeof input.assertion?.id !== 'string' || typeof input.assertion.response?.signature !== 'string') {
    throw new OrgKeyRefusal(403, 'passkey_invalid', 'Passkey assertion is malformed');
  }

  const challenge = await prisma.orgKeySignChallenge.findFirst({
    where: { nonce: input.nonce, userId: input.userId, keyId: input.keyId },
  });
  // F-A: the challenge is bound to the origin it was issued for. A request from
  // any other origin, or for any other message, does not match the challenge.
  if (!challenge || challenge.messageDigest !== messageDigestHex(input.message) || challenge.origin !== input.origin) {
    throw new OrgKeyRefusal(403, 'challenge_invalid', 'Signing challenge does not match this request');
  }
  if (challenge.consumedAt) throw new OrgKeyRefusal(403, 'challenge_consumed', 'Signing challenge was already used');
  if (challenge.expiresAt.getTime() <= Date.now()) {
    throw new OrgKeyRefusal(403, 'challenge_expired', 'Signing challenge has expired');
  }

  // F-F: the message kind is derived here from the stored record. No caller-supplied kind is trusted.
  const record = await loadOrgKeyRecord(prisma, input.keyId);
  if (!record) throw new OrgKeyRefusal(404, 'key_not_found', 'Key not found');
  const activeGrant = await findActiveOrgGrant(prisma, input.userId, input.keyId);
  if (!activeGrant || activeGrant.grantId !== challenge.grantId) {
    throw new OrgKeyRefusal(403, 'grant_revoked', 'No active grant on this key');
  }
  const classification = classifyOrgKeyMessage(input.message, {
    record,
    requestingOrigin: input.origin,
    grant: { grantId: activeGrant.grantId, role: activeGrant.role },
  });
  if (!classification.ok) throw new OrgKeyRefusal(403, classification.refusal, 'Message is not signable by this key');
  const requiredRole = classification.role;

  const passkey = await prisma.passkey.findFirst({
    where: { userId: input.userId, credentialID: input.assertion.id },
  });
  if (!passkey) throw new OrgKeyRefusal(403, 'passkey_required', 'A fresh passkey assertion is required');

  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verification = await verifyAuthenticationResponse({
      response: input.assertion,
      expectedChallenge: orgKeySignChallenge({
        keyId: challenge.keyId,
        grantId: challenge.grantId,
        nonce: challenge.nonce,
        messageDigest: challenge.messageDigest,
        origin: challenge.origin,
      }).toString('base64url'),
      expectedOrigin: input.expectedOrigin,
      expectedRPID: input.rpID,
      credential: {
        id: passkey.credentialID,
        publicKey: Buffer.from(passkey.publicKey, 'base64'),
        counter: passkey.counter,
      },
      requireUserVerification: true,
    });
  } catch {
    throw new OrgKeyRefusal(403, 'passkey_invalid', 'Passkey assertion did not verify');
  }
  if (!verification.verified) {
    throw new OrgKeyRefusal(403, 'passkey_invalid', 'Passkey assertion did not verify');
  }

  const assertionHash = canonicalSignatureHash(input.assertion.response.signature, passkeyUsesEs256(passkey.publicKey));
  const messageDigest = messageDigestHex(input.message);

  try {
    return await prisma.$transaction(async (tx) => {
      // F3: the grant row is locked FOR SHARE for the rest of the transaction.
      const grant = await lockActiveGrant(tx, { grantId: challenge.grantId, keyId: input.keyId, userId: input.userId });
      if (!grant) throw new OrgKeyRefusal(403, 'grant_revoked', 'No active grant on this key');
      if (requiredRole && !roleSatisfies(grant.role as OrgRole, requiredRole)) {
        throw new OrgKeyRefusal(403, 'org_space_role_insufficient', 'The signing role no longer satisfies this message');
      }

      // Single use: the challenge is consumed only if still unused and unexpired.
      // A concurrent request that loses this race gets challenge_consumed; the
      // rollback on any later failure restores consumedAt to NULL.
      const consumed = await tx.orgKeySignChallenge.updateMany({
        where: { id: challenge.id, consumedAt: null, expiresAt: { gt: new Date() } },
        data: { consumedAt: new Date() },
      });
      if (consumed.count !== 1) {
        throw new OrgKeyRefusal(403, 'challenge_consumed', 'Signing challenge was already used or has expired');
      }

      const key = await tx.ethereumKey.findFirst({
        where: { id: input.keyId, custody: 'ORG', userId: null, archivedAt: null },
      });
      if (!key || !key.sealedBlob) throw new OrgKeyRefusal(404, 'key_not_found', 'Key not found');

      await tx.passkey.update({
        where: { id: passkey.id },
        data: { counter: verification.authenticationInfo.newCounter },
      });
      await tx.orgKeySignatureAudit.create({
        data: {
          keyId: input.keyId,
          grantId: challenge.grantId,
          actorUserId: input.userId,
          origin: input.origin,
          messageDigest,
          role: grant.role,
          messageKind: classification.kind,
          passkeyAssertionHash: assertionHash,
          challengeId: challenge.id,
        },
      });

      const sealingKey = await deriveKeyForRecord(tee, key);
      let privateKey: Hex;
      try {
        privateKey = (await unseal(key.sealedBlob, sealingKey)) as Hex;
      } finally {
        sealingKey.fill(0);
      }
      const account = createWalletFromPrivateKey(privateKey);
      // The rendered statement text is what the consent screen showed. It is signed, not the raw JSON.
      const signature = await account.signMessage({ message: classification.text });
      return { signature, address: key.address };
    });
  } catch (error) {
    if (error instanceof OrgKeyRefusal) throw error;
    if ((error as { code?: string }).code === 'P2002') {
      throw new OrgKeyRefusal(403, 'assertion_consumed', 'Passkey assertion was already used');
    }
    throw error;
  }
}
