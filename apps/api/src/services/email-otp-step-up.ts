import { randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { Resend } from 'resend';
import type { PrismaClient } from '@openkey/db';

const TTL_MS = 5 * 60 * 1000;
const ATTEMPTS = 3;
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const isDev = process.env.NODE_ENV !== 'production' && process.env.TEE_MODE !== 'production';

/**
 * A code proves one purpose only. A linking code stamps `session.lastEmailOtpAt`
 * (link and unlink); every other purpose records its own single-use marker on
 * the session, so a code mailed for one purpose never authorizes another.
 */
export type StepUpPurpose = 'link' | 'delete_account' | 'passkey_register' | 'passkey_remove';
type MarkerPurpose = Exclude<StepUpPurpose, 'link'>;

export function parseStepUpPurpose(value: unknown): StepUpPurpose | null {
  if (value === undefined || value === 'link') return 'link';
  if (value === 'delete_account' || value === 'passkey_register' || value === 'passkey_remove') return value;
  return null;
}

const CODE_PREFIX: Record<StepUpPurpose, string> = {
  link: 'openkey-account-step-up-otp',
  delete_account: 'openkey-account-delete-otp',
  passkey_register: 'openkey-passkey-register-otp',
  passkey_remove: 'openkey-passkey-remove-otp',
};

export function stepUpIdentifier(sessionId: string, email: string, purpose: StepUpPurpose = 'link'): string {
  return `${CODE_PREFIX[purpose]}:${sessionId}:${email.toLowerCase()}`;
}

const MARKER_PREFIX: Record<MarkerPurpose, string> = {
  delete_account: 'openkey-account-delete-step-up',
  passkey_register: 'openkey-passkey-register-step-up',
  passkey_remove: 'openkey-passkey-remove-step-up',
};

/** The fresh (five-minute), single-use proof a verified code leaves on its session. */
export function stepUpMarkerIdentifier(purpose: MarkerPurpose, sessionId: string): string {
  return `${MARKER_PREFIX[purpose]}:${sessionId}`;
}

/**
 * How a passkey-registration marker was earned. An email code verified for
 * `passkey_register` writes `email_step_up`; a session created by a verified
 * email code (sign-in or sign-up) carries the same proof from its creation.
 */
export type PasskeyRegisterGrant = 'email_step_up' | 'email_sign_in' | 'account_creation';

const EMAILS: Record<StepUpPurpose, { subject: string; html: (code: string) => string }> = {
  link: {
    subject: 'Your OpenKey account linking code',
    html: (code) => `<p>Use this code to link or unlink a sign-in method on your OpenKey account:</p><p>${code}</p><p>It expires in 5 minutes. If you did not request this, ignore this email.</p>`,
  },
  delete_account: {
    subject: 'Your code to delete your OpenKey account',
    html: (code) => `<p>Use this code to permanently delete your OpenKey account and its keys:</p><p>${code}</p><p>It expires in 5 minutes. If you did not request this, do not share it and ignore this email.</p>`,
  },
  passkey_register: {
    subject: 'Your code to add a passkey to your OpenKey account',
    html: (code) => `<p>Use this code to add a new passkey to your OpenKey account:</p><p>${code}</p><p>It expires in 5 minutes. If you did not request this, do not share it and ignore this email.</p>`,
  },
  passkey_remove: {
    subject: 'Your code to remove a passkey from your OpenKey account',
    html: (code) => `<p>Use this code to remove a passkey from your OpenKey account:</p><p>${code}</p><p>It expires in 5 minutes. If you did not request this, do not share it and ignore this email.</p>`,
  },
};

export async function sendAccountStepUpCode(
  database: PrismaClient, sessionId: string, email: string, purpose: StepUpPurpose = 'link',
): Promise<'sent' | 'pending' | 'unavailable'> {
  if (!resend && !isDev) return 'unavailable';
  const identifier = stepUpIdentifier(sessionId, email, purpose);
  const now = new Date();
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  const issued = await database.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "session" WHERE id = ${sessionId} FOR UPDATE`;
    const existing = await tx.verification.findFirst({ where: { identifier, expiresAt: { gt: now } } });
    if (existing) return false;
    await tx.verification.deleteMany({ where: { identifier } });
    await tx.verification.create({ data: {
      id: randomUUID(), identifier, value: `${code}:0`,
      expiresAt: new Date(now.getTime() + TTL_MS),
    } });
    return true;
  });
  if (!issued) return 'pending';
  if (resend) {
    try {
      const result = await resend.emails.send({
        from: 'OpenKey <noreply@openkey.so>',
        to: email,
        subject: EMAILS[purpose].subject,
        html: EMAILS[purpose].html(code),
      });
      if (result.error) throw result.error;
    } catch {
      await database.verification.deleteMany({ where: { identifier, value: `${code}:0` } });
      return 'unavailable';
    }
  }
  return 'sent';
}

export async function verifyAccountStepUpCode(
  database: PrismaClient, sessionId: string, email: string, code: unknown, purpose: StepUpPurpose = 'link',
): Promise<boolean> {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return false;
  const identifier = stepUpIdentifier(sessionId, email, purpose);
  const now = new Date();
  return database.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "session" WHERE id = ${sessionId} FOR UPDATE`;
    const row = await tx.verification.findFirst({ where: { identifier } });
    if (!row) return false;
    if (row.expiresAt <= now) {
      await tx.verification.deleteMany({ where: { id: row.id } });
      return false;
    }
    const separator = row.value.lastIndexOf(':');
    const stored = row.value.slice(0, separator);
    const attempts = Number(row.value.slice(separator + 1));
    if (attempts >= ATTEMPTS) return false;
    if (!timingSafeEqual(Buffer.from(code), Buffer.from(stored))) {
      await tx.verification.update({ where: { id: row.id }, data: { value: `${stored}:${attempts + 1}` } });
      return false;
    }
    await tx.verification.deleteMany({ where: { id: row.id } });
    if (purpose === 'link') {
      await tx.session.update({ where: { id: sessionId }, data: { lastEmailOtpAt: now } });
    } else {
      await writeStepUpMarker(tx, purpose, sessionId, purpose === 'passkey_register' ? 'email_step_up' : now.toISOString(), now);
    }
    return true;
  });
}

export async function hasFreshEmailStepUp(database: PrismaClient, sessionId: string): Promise<boolean> {
  const session = await database.session.findUnique({ where: { id: sessionId }, select: { lastEmailOtpAt: true } });
  const at = session?.lastEmailOtpAt?.getTime();
  return at !== undefined && at <= Date.now() && Date.now() - at < TTL_MS;
}

type VerificationClient = Pick<PrismaClient, 'verification'>;

/** Replaces the session's marker for `purpose` with a fresh five-minute one. */
export async function writeStepUpMarker(
  database: VerificationClient, purpose: MarkerPurpose, sessionId: string, value: string, now = new Date(),
): Promise<void> {
  const identifier = stepUpMarkerIdentifier(purpose, sessionId);
  await database.verification.deleteMany({ where: { identifier } });
  await database.verification.create({ data: {
    id: randomUUID(), identifier, value, expiresAt: new Date(now.getTime() + TTL_MS),
  } });
}

/** The unexpired marker's value for `purpose` on this session, or null. */
export async function freshStepUpMarker(
  database: VerificationClient, purpose: MarkerPurpose, sessionId: string, now = new Date(),
): Promise<string | null> {
  const row = await database.verification.findFirst({
    where: { identifier: stepUpMarkerIdentifier(purpose, sessionId), expiresAt: { gt: now } },
    select: { value: true },
  });
  return row?.value ?? null;
}

/** Spends the marker for `purpose`; returns its value, or null if none was fresh. */
export async function consumeStepUpMarker(
  database: VerificationClient, purpose: MarkerPurpose, sessionId: string, now = new Date(),
): Promise<string | null> {
  const identifier = stepUpMarkerIdentifier(purpose, sessionId);
  const row = await database.verification.findFirst({
    where: { identifier, expiresAt: { gt: now } }, select: { id: true, value: true },
  });
  if (!row) return null;
  // One DELETE is the single-use gate: concurrent spends race on the same row.
  const consumed = await database.verification.deleteMany({
    where: { id: row.id, identifier, value: row.value, expiresAt: { gt: now } },
  });
  return consumed.count === 1 ? row.value : null;
}

export async function hasFreshDeleteStepUp(database: VerificationClient, sessionId: string, now = new Date()): Promise<boolean> {
  return await freshStepUpMarker(database, 'delete_account', sessionId, now) !== null;
}

/** Spends the deletion proof inside the deletion transaction; false if none is fresh. */
export async function consumeDeleteStepUp(database: VerificationClient, sessionId: string, now = new Date()): Promise<boolean> {
  return await consumeStepUpMarker(database, 'delete_account', sessionId, now) !== null;
}
