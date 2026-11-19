// TC-3442: an approval can need a passkey assertion bound to the exact request.
//
// The account's `passkeyApprovalMode` says which approvals: ALWAYS (every one), SENSITIVE (the ones the review
// screen marks Sensitive, plus requests that cannot be classified, plus grants of signing power used later without a
// button) or NEVER. The mode only applies while the account has a passkey that counts for step-up (TC-1198): only
// such a passkey can confirm an approval, so a passkey enrolled on a session alone never can.
//
// Binding: the WebAuthn challenge is a hash over the route's purpose, the user, the session, the digest of the exact
// request and a random nonce. The challenge is stored in `verification`, lives five minutes, and is spent before the
// assertion is checked, so it can confirm one request once. The assertion does not stamp the session: it approves
// this request only.

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { decodeHexUtf8, parseCapabilityReview, parseSiweChainId } from '@openkey/capability-review';
import type { PrismaClient } from '@openkey/db';
import { log } from '../log';

export const PASSKEY_APPROVAL_MODES = ['ALWAYS', 'SENSITIVE', 'NEVER'] as const;
export type PasskeyApprovalMode = (typeof PASSKEY_APPROVAL_MODES)[number];
export type ApprovalSensitivity = 'sensitive' | 'standard';

const MODE_RANK: Record<PasskeyApprovalMode, number> = { NEVER: 0, SENSITIVE: 1, ALWAYS: 2 };

export function parsePasskeyApprovalMode(value: unknown): PasskeyApprovalMode | null {
  return typeof value === 'string' && (PASSKEY_APPROVAL_MODES as readonly string[]).includes(value)
    ? value as PasskeyApprovalMode
    : null;
}

/** True when `to` asks for a passkey on fewer approvals than `from`. */
export function lowersPasskeyApprovalMode(from: PasskeyApprovalMode, to: PasskeyApprovalMode): boolean {
  return MODE_RANK[to] < MODE_RANK[from];
}

export function passkeyApprovalRequired(mode: PasskeyApprovalMode, sensitivity: ApprovalSensitivity): boolean {
  return mode === 'ALWAYS' || (mode === 'SENSITIVE' && sensitivity === 'sensitive');
}

type ApprovalDatabase = Pick<PrismaClient, 'user' | 'passkey' | 'verification' | '$transaction'>;

/** The stored mode, and the mode in force: NEVER while the account has no passkey that counts for step-up. */
export async function passkeyApprovalModes(
  db: Pick<PrismaClient, 'user' | 'passkey'>, userId: string,
): Promise<{ mode: PasskeyApprovalMode; effectiveMode: PasskeyApprovalMode; stepUpPasskeys: number } | null> {
  const [user, stepUpPasskeys] = await Promise.all([
    db.user.findUnique({ where: { id: userId }, select: { passkeyApprovalMode: true } }),
    db.passkey.count({ where: { userId, countsForStepUp: true } }),
  ]);
  if (!user) return null;
  // An unknown stored value (the column has a CHECK) fails closed to the strictest mode.
  const mode = parsePasskeyApprovalMode(user.passkeyApprovalMode) ?? 'ALWAYS';
  return { mode, effectiveMode: stepUpPasskeys > 0 ? mode : 'NEVER', stepUpPasskeys };
}

function siweSensitivity(text: string, signerAddress: string): ApprovalSensitivity | null {
  // No manifest and no requester: severity is structural only, so nothing the app says can lower it.
  const model = parseCapabilityReview({
    message: text,
    signer: { label: 'OpenKey', address: signerAddress, chainId: parseSiweChainId(text) ?? 1, provenance: 'managed' },
    editable: false,
    metadataTrust: { status: 'unsigned', reason: 'server classification' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: '', verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none',
      manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false,
    },
  });
  if (model.protocol === 'legacy-message') return null;
  if (model.protocol !== 'siwe-plain' && model.protocol !== 'tinycloud-siwe-recap') return 'sensitive';
  return model.permissions.some((grant) => grant.severity === 'sensitive') ? 'sensitive' : 'standard';
}

/**
 * Sensitivity of a message as the signer will cover it. A SIWE message is as sensitive as its most sensitive grant,
 * by the classifier the review screen uses. Anything else (plain text, bytes) cannot be classified and is sensitive.
 * `0x` hex is read both as written and as UTF-8, like the other signing guards.
 */
export function messageApprovalSensitivity(message: string, signerAddress: string): ApprovalSensitivity {
  const candidates = [message];
  const decoded = decodeHexUtf8(message);
  if (decoded !== null) candidates.push(decoded);
  const results = candidates.map((text) => siweSensitivity(text, signerAddress));
  if (results.every((result) => result === null)) return 'sensitive';
  return results.includes('sensitive') ? 'sensitive' : 'standard';
}

/** Digest of the parts that identify one request. Each part is length-prefixed, so parts cannot run together. */
export function approvalRequestDigest(...parts: string[]): string {
  const hash = createHash('sha256');
  for (const part of parts) {
    const bytes = Buffer.from(part, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest('hex');
}

/** What one approval is bound to: the route's purpose and the digest of the exact request. */
export type ApprovalBinding = { purpose: string; requestDigest: string };
/**
 * Who approves: the account and the session the challenge is bound to. Routes behind the session middleware always
 * have a session; without one no challenge is issued and no assertion verifies, so an approval that needs the passkey
 * is refused.
 */
export type ApprovalSubject = { sessionId: string | null; userId: string };
export type RelyingParty = { rpID: string; origin: string };

export function relyingParty(): RelyingParty {
  return { rpID: process.env.WEBAUTHN_RP_ID!, origin: process.env.WEBAUTHN_ORIGIN! };
}

const CHALLENGE_DOMAIN = 'openkey-approval-v1';
const CHALLENGE_PREFIX = 'openkey-approval-passkey';
export const APPROVAL_PASSKEY_TTL_MS = 5 * 60 * 1000;
const MAX_LIVE_CHALLENGES_PER_SESSION = 16;

const sha256 = (value: string) => createHash('sha256').update(value).digest('base64url');
const sessionPrefix = (sessionId: string) => `${CHALLENGE_PREFIX}:${sessionId}:`;

export type ApprovalPasskeyOffer = { challengeToken: string; options: PublicKeyCredentialRequestOptionsJSON };

/** A challenge for one request, or null when the account has no passkey that counts for step-up. */
export async function createApprovalPasskeyChallenge(
  db: ApprovalDatabase, subject: ApprovalSubject, binding: ApprovalBinding, rp = relyingParty(), now = new Date(),
): Promise<ApprovalPasskeyOffer | null> {
  if (subject.sessionId === null) return null;
  const passkeys = await db.passkey.findMany({
    where: { userId: subject.userId, countsForStepUp: true }, select: { credentialID: true, transports: true },
  });
  if (passkeys.length === 0) return null;
  const challenge = createHash('sha256');
  for (const part of [CHALLENGE_DOMAIN, binding.purpose, subject.userId, subject.sessionId, binding.requestDigest]) {
    challenge.update(approvalRequestDigest(part));
  }
  challenge.update(randomBytes(32));
  const options = await generateAuthenticationOptions({
    rpID: rp.rpID,
    userVerification: 'required',
    challenge: new Uint8Array(challenge.digest()),
    allowCredentials: passkeys.map((passkey) => ({
      id: passkey.credentialID,
      transports: passkey.transports ? passkey.transports.split(',') as AuthenticatorTransportFuture[] : undefined,
    })),
  });
  const challengeToken = randomBytes(32).toString('base64url');
  const prefix = sessionPrefix(subject.sessionId);
  await db.$transaction(async (tx) => {
    await tx.verification.deleteMany({ where: { identifier: { startsWith: prefix }, expiresAt: { lte: now } } });
    const live = await tx.verification.findMany({
      where: { identifier: { startsWith: prefix } }, orderBy: { createdAt: 'desc' }, select: { id: true },
      skip: MAX_LIVE_CHALLENGES_PER_SESSION - 1,
    });
    if (live.length > 0) await tx.verification.deleteMany({ where: { id: { in: live.map((row) => row.id) } } });
    await tx.verification.create({ data: {
      id: randomUUID(),
      identifier: `${prefix}${sha256(challengeToken)}`,
      userId: subject.userId,
      value: JSON.stringify({ challenge: options.challenge, ...binding }),
      expiresAt: new Date(now.getTime() + APPROVAL_PASSKEY_TTL_MS),
    } });
  });
  return { challengeToken, options };
}

export type ApprovalPasskeyResult = 'verified' | 'invalid' | 'not_step_up';

/** Checks an assertion for this request, spending its challenge whatever the outcome. */
export async function verifyApprovalPasskey(
  db: ApprovalDatabase, subject: ApprovalSubject, binding: ApprovalBinding, assertion: unknown,
  rp = relyingParty(), now = new Date(),
): Promise<ApprovalPasskeyResult> {
  const body = assertion as { challengeToken?: unknown; response?: unknown } | null | undefined;
  const response = body?.response as AuthenticationResponseJSON | undefined;
  if (typeof body?.challengeToken !== 'string' || !response || typeof response !== 'object' || typeof response.id !== 'string'
    || subject.sessionId === null) {
    return 'invalid';
  }
  const identifier = `${sessionPrefix(subject.sessionId)}${sha256(body.challengeToken)}`;
  const row = await db.verification.findFirst({ where: { identifier, userId: subject.userId, expiresAt: { gt: now } } });
  if (!row) return 'invalid';
  const consumed = await db.verification.deleteMany({ where: { id: row.id, identifier, value: row.value } });
  if (consumed.count !== 1) return 'invalid';
  const stored = JSON.parse(row.value) as { challenge: string } & ApprovalBinding;
  if (stored.purpose !== binding.purpose || stored.requestDigest !== binding.requestDigest) return 'invalid';

  const passkey = await db.passkey.findFirst({ where: { credentialID: response.id, userId: subject.userId } });
  if (!passkey) return 'invalid';
  if (!passkey.countsForStepUp) return 'not_step_up';
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: stored.challenge,
    expectedOrigin: rp.origin,
    expectedRPID: rp.rpID,
    credential: {
      id: passkey.credentialID,
      publicKey: new Uint8Array(Buffer.from(passkey.publicKey, 'base64')),
      counter: passkey.counter,
      transports: passkey.transports ? passkey.transports.split(',') as AuthenticatorTransportFuture[] : undefined,
    },
    requireUserVerification: true,
  }).catch(() => null);
  if (!verification?.verified || verification.authenticationInfo.userVerified !== true) return 'invalid';
  await db.passkey.update({ where: { id: passkey.id }, data: { counter: verification.authenticationInfo.newCounter } });
  return 'verified';
}

export const PASSKEY_APPROVAL_REQUIRED = {
  error: 'This approval needs your passkey. Tap Approve to try again.',
  code: 'passkey_approval_required',
} as const;
export const PASSKEY_APPROVAL_INVALID = {
  error: "Your passkey didn't confirm this. Tap Approve to try again.",
  code: 'passkey_approval_invalid',
} as const;
// A passkey enrolled without step-up gets the same words as any assertion that did not confirm; the code tells them apart.
export const PASSKEY_APPROVAL_NOT_STEP_UP = {
  error: PASSKEY_APPROVAL_INVALID.error,
  code: 'passkey_not_step_up_capable',
} as const;

export type ApprovalPasskeyRefusal =
  | typeof PASSKEY_APPROVAL_REQUIRED | typeof PASSKEY_APPROVAL_INVALID | typeof PASSKEY_APPROVAL_NOT_STEP_UP;

/** Does this approval need a passkey under the account's mode in force? */
export async function approvalNeedsPasskey(
  db: ApprovalDatabase, userId: string, sensitivity: ApprovalSensitivity,
): Promise<boolean> {
  // Without a passkey that counts for step-up the mode in force is NEVER, whatever is stored.
  if (await db.passkey.count({ where: { userId, countsForStepUp: true } }) === 0) return false;
  const user = await db.user.findUnique({ where: { id: userId }, select: { passkeyApprovalMode: true } });
  // An account that cannot be read is not approved here; an unknown stored value is the strictest mode.
  const mode = user ? parsePasskeyApprovalMode(user.passkeyApprovalMode) ?? 'ALWAYS' : 'ALWAYS';
  return passkeyApprovalRequired(mode, sensitivity);
}

/**
 * The gate a route runs before it unseals a key: null when the approval may go ahead, else the refusal body (403).
 * Only the outcome is logged, never the assertion.
 */
export async function checkApprovalPasskey(
  db: ApprovalDatabase, subject: ApprovalSubject, binding: ApprovalBinding, sensitivity: ApprovalSensitivity,
  assertion: unknown, rp = relyingParty(), now = new Date(),
): Promise<ApprovalPasskeyRefusal | null> {
  if (!await approvalNeedsPasskey(db, subject.userId, sensitivity)) return null;
  if (assertion === undefined || assertion === null) {
    log('info', 'approval_passkey_refused', PASSKEY_APPROVAL_REQUIRED.code);
    return PASSKEY_APPROVAL_REQUIRED;
  }
  const result = await verifyApprovalPasskey(db, subject, binding, assertion, rp, now);
  if (result === 'verified') {
    log('info', 'approval_passkey_verified');
    return null;
  }
  const refusal = result === 'not_step_up' ? PASSKEY_APPROVAL_NOT_STEP_UP : PASSKEY_APPROVAL_INVALID;
  log('info', 'approval_passkey_refused', refusal.code);
  return refusal;
}

/**
 * What an approval screen receives with its preview: whether Approve needs the passkey and, when it does, the
 * challenge for this request, so the tap goes straight to the passkey prompt.
 */
export async function approvalPasskeyOffer(
  db: ApprovalDatabase, subject: ApprovalSubject, binding: ApprovalBinding, sensitivity: ApprovalSensitivity,
  rp = relyingParty(), now = new Date(),
): Promise<{ required: false } | ({ required: true } & ApprovalPasskeyOffer)> {
  if (!await approvalNeedsPasskey(db, subject.userId, sensitivity)) return { required: false };
  const offer = await createApprovalPasskeyChallenge(db, subject, binding, rp, now);
  // No offer means the passkey that counts was removed since the mode was read, or there is no session; the route
  // then refuses the approval without an assertion, failing closed.
  return offer ? { required: true, ...offer } : { required: false };
}
