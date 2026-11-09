import { randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { Resend } from 'resend';
import type { PrismaClient } from '@openkey/db';

const TTL_MS = 5 * 60 * 1000;
const ATTEMPTS = 3;
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const isDev = process.env.NODE_ENV !== 'production' && process.env.TEE_MODE !== 'production';

export function stepUpIdentifier(sessionId: string, email: string): string {
  return `openkey-account-step-up-otp:${sessionId}:${email.toLowerCase()}`;
}

export async function sendAccountStepUpCode(database: PrismaClient, sessionId: string, email: string): Promise<'sent' | 'pending' | 'unavailable'> {
  if (!resend && !isDev) return 'unavailable';
  const identifier = stepUpIdentifier(sessionId, email);
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
        subject: 'Your OpenKey account linking code',
        html: `<p>Use this code to link or unlink a sign-in method on your OpenKey account:</p><p>${code}</p><p>It expires in 5 minutes. If you did not request this, ignore this email.</p>`,
      });
      if (result.error) throw result.error;
    } catch {
      await database.verification.deleteMany({ where: { identifier, value: `${code}:0` } });
      return 'unavailable';
    }
  }
  return 'sent';
}

export async function verifyAccountStepUpCode(database: PrismaClient, sessionId: string, email: string, code: unknown): Promise<boolean> {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return false;
  const identifier = stepUpIdentifier(sessionId, email);
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
    await tx.session.update({ where: { id: sessionId }, data: { lastEmailOtpAt: now } });
    return true;
  });
}

export async function hasFreshEmailStepUp(database: PrismaClient, sessionId: string): Promise<boolean> {
  const session = await database.session.findUnique({ where: { id: sessionId }, select: { lastEmailOtpAt: true } });
  const at = session?.lastEmailOtpAt?.getTime();
  return at !== undefined && at <= Date.now() && Date.now() - at < TTL_MS;
}
