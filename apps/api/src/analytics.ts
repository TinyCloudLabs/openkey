// OpenKey API - OAuth analytics instrumentation
// Tracks daily authorization, token exchange, and unique user metrics per client
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

function getToday(): Date {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return today;
}

export async function trackAuthorization(clientId: string) {
  const today = getToday();

  await prisma.oauthDailyStats.upsert({
    where: { clientId_date: { clientId, date: today } },
    update: { totalAuthorizations: { increment: 1 } },
    create: { clientId, date: today, totalAuthorizations: 1 },
  });
}

export async function trackTokenExchange(clientId: string) {
  const today = getToday();

  await prisma.oauthDailyStats.upsert({
    where: { clientId_date: { clientId, date: today } },
    update: { totalTokenExchanges: { increment: 1 } },
    create: { clientId, date: today, totalTokenExchanges: 1 },
  });
}

export async function trackUniqueUser(clientId: string) {
  const today = getToday();

  // Count distinct users for this client today from OauthAccessToken
  const count = await prisma.oauthAccessToken.groupBy({
    by: ['userId'],
    where: {
      clientId,
      createdAt: { gte: today },
    },
  });

  await prisma.oauthDailyStats.upsert({
    where: { clientId_date: { clientId, date: today } },
    update: { uniqueUsers: count.length },
    create: { clientId, date: today, uniqueUsers: count.length },
  });
}
