import { EncryptJWT, jwtDecrypt } from 'jose';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { APIError, createAuthEndpoint } from 'better-auth/api';
import type { PrismaClient } from '@openkey/db';
import { reviewerBrowserRequest } from './reviewer-auth';
import { appleReviewEnabled } from './reviewer-apple-policy';
import { holdReviewer, lockReviewer, normalizedReviewerEmail, reviewerCodeMatches, reviewerFailure } from './reviewer-accounts';
import { retireReviewerOwner } from './reviewer-cleanup';

const COOKIE = '__Secure-openkey-review-delete';
const options = { httpOnly: true, secure: true, sameSite: 'strict' as const, path: '/', maxAge: 300 };
const refusal = () => new APIError('FORBIDDEN', { code: 'REVIEWER_DELETE_REFUSED', message: "Couldn't verify the app review account. Check the review account and code, then try again." });
const requireBrowser = (ctx: any, origin: string) => {
  if (!appleReviewEnabled() || !ctx.request || !reviewerBrowserRequest(ctx.request.headers, origin)) throw refusal();
};
export function reviewerDeleteEndpoints(database: PrismaClient, origin: string) {
  return {
    reviewerDeleteIntent: createAuthEndpoint('/reviewer/delete-intent', { method: 'POST', requireHeaders: true }, async ctx => {
      requireBrowser(ctx, origin);
      const binding = await database.reviewerAccount.findUnique({ where: { store: 'apple' } });
      const intent = await new EncryptJWT({ store: 'apple', userId: binding?.userId ?? randomUUID(), epoch: binding?.installEpoch ?? -1,
        nonce: randomBytes(32).toString('base64url'), expiresAt: Date.now() + 300_000 })
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).setExpirationTime('5m')
        .encrypt(createHash('sha256').update(ctx.context.secret).digest());
      ctx.setCookie(COOKIE, intent, options);
      return ctx.json({ success: true });
    }),
    reviewerDelete: createAuthEndpoint('/reviewer/delete', { method: 'POST', requireHeaders: true }, async ctx => {
      try {
        requireBrowser(ctx, origin);
        let intent: Record<string, unknown>;
        try { intent = (await jwtDecrypt(ctx.getCookie(COOKIE) || '', createHash('sha256').update(ctx.context.secret).digest(),
          { keyManagementAlgorithms: ['dir'], contentEncryptionAlgorithms: ['A256GCM'] })).payload; }
        catch { throw refusal(); }
        const body = ctx.body as { email?: unknown; code?: unknown; confirmation?: unknown } | undefined;
        await database.$transaction(async tx => {
          const binding = await lockReviewer(tx, 'apple');
          if (!intent || intent.store !== 'apple' || typeof intent.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(intent.nonce)
            || typeof intent.expiresAt !== 'number' || intent.expiresAt <= Date.now() || intent.expiresAt > Date.now() + 300_000
            || intent.userId !== binding.userId || intent.epoch !== binding.installEpoch
            || normalizedReviewerEmail(body?.email) !== binding.email || body?.confirmation !== 'DELETE MY ACCOUNT'
            || !reviewerCodeMatches(binding, body?.code)) throw refusal();
          await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${binding.userId} FOR UPDATE`;
          if (await tx.passkey.count({ where: { userId: binding.userId! } })) throw refusal();
          // Tombstone is committed before the live owner/key can disappear.
          await retireReviewerOwner(tx, binding);
          await holdReviewer(tx, binding);
          await tx.ethereumKey.deleteMany({ where: { userId: binding.userId! } });
          await tx.user.delete({ where: { id: binding.userId! } });
          await tx.reviewerAccount.update({ where: { store: 'apple' }, data: { userId: null, keyId: null, spaceId: null,
            seededAt: null, seedStartedAt: null, writerExpiresAt: null } });
        });
        ctx.setCookie(COOKIE, '', { ...options, maxAge: 0 });
        return ctx.json({ deleted: true });
      } catch {
        const binding = await database.reviewerAccount.findUnique({ where: { store: 'apple' }, include: { user: true } });
        await reviewerFailure(binding);
        throw refusal();
      }
    }),
  };
}
