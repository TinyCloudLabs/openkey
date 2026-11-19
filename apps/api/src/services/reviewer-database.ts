import type { PrismaClient } from '@openkey/db';
import {
  REVIEWER_MAX_SECONDS, capturedReviewer, reviewerActive, reviewerForUser,
} from './reviewer-accounts';

/** Provider writes may finish after an unset. Their captured epoch must survive the write. */
export function withReviewerDatabase(database: PrismaClient): PrismaClient {
  async function currentRead(model: string, args: any, query: (args: any) => Promise<any>) {
    const bindings = await database.reviewerAccount.findMany({ include: { user: true } });
    const active = bindings.filter((binding) => reviewerActive(binding));
    const alternatives: object[] = [{ user: { reviewerBinding: null, lockedAt: null, reviewerHoldAt: null } }];
    if (model === 'Session' || model === 'OauthConsent') {
      for (const binding of active) alternatives.push({
        userId: binding.userId, reviewerEpoch: binding.installEpoch,
        user: { lockedAt: null, reviewerHoldAt: null },
      });
    } else {
      for (const binding of active) {
        const sessions = await database.session.findMany({
          where: { userId: binding.userId!, reviewerEpoch: binding.installEpoch, expiresAt: { gt: new Date() } },
          select: { id: true },
        });
        alternatives.push({ userId: binding.userId, sessionId: { in: sessions.map((session) => session.id) } });
      }
    }
    return query({ ...args, where: { ...args.where, AND: [args.where ?? {}, { OR: alternatives }] } });
  }

  async function currentWrite(model: string, args: any, query: (args: any) => Promise<any>) {
    const data = args.data;
    const userId = data?.userId;
    if (typeof userId !== 'string') return query(args);
    const binding = await reviewerForUser(database, userId);
    if (!binding) return query(args);
    const captured = capturedReviewer();
    if (captured?.userId !== userId || !reviewerActive(binding, captured.epoch)) throw new Error('Reviewer authority ended');
    const stamped = { ...data };
    if (model === 'Session' || model === 'OauthConsent') stamped.reviewerEpoch = captured.epoch;
    if (data.expiresAt) {
      let limit = (model === 'Session' && data.createdAt ? new Date(data.createdAt).getTime() : Date.now()) + REVIEWER_MAX_SECONDS * 1000;
      if (model === 'OauthAccessToken' || model === 'OauthRefreshToken') {
        const source = await database.session.findFirst({
          where: { id: data.sessionId ?? '', userId, reviewerEpoch: captured.epoch, expiresAt: { gt: new Date() } },
        });
        if (!source) throw new Error('Reviewer authority ended');
        limit = Math.min(limit, source.createdAt.getTime() + REVIEWER_MAX_SECONDS * 1000);
      }
      stamped.expiresAt = new Date(Math.min(new Date(data.expiresAt).getTime(), limit));
    }
    return query({ ...args, data: stamped });
  }

  const reads = {
    findFirst: ({ model, args, query }: any) => currentRead(model, args, query),
    findUnique: ({ model, args, query }: any) => currentRead(model, args, query),
    findMany: ({ model, args, query }: any) => currentRead(model, args, query),
    create: ({ model, args, query }: any) => currentWrite(model, args, query),
  };
  return database.$extends({
    query: {
      session: reads,
      oauthConsent: reads,
      oauthAccessToken: reads,
      oauthRefreshToken: reads,
      verification: {
        create: async ({ args, query }: any) => {
          const captured = capturedReviewer();
          if (!captured) return query(args);
          let value: any;
          try { value = JSON.parse(args.data.value); } catch { return query(args); }
          if (value.type !== 'authorization_code') return query(args);
          if (value.userId !== captured.userId) throw new Error('Reviewer authority ended');
          return query({ ...args, data: {
            ...args.data, value: JSON.stringify({ ...value, reviewerEpoch: captured.epoch }),
          } });
        },
      },
    },
  }) as unknown as PrismaClient;
}
