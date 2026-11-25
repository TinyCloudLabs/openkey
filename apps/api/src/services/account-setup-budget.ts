// What one account may ask of the account setup routes in an hour, across all its setup requests and sessions.
//
// The email code and the step-up attempts are limited per request and session (account-setup-step-up.ts: three wrong
// guesses a code), and a request or a session can be replaced. These budgets are keyed by the user, so a new request
// or a new session does not reset them:
//   send    codes mailed to the owner
//   verify  step-up attempts (a code or a passkey assertion) that did not confirm
//
// Each budget has two limits in one window: the user's total, and a share of it for one session, so a single session
// cannot spend the whole total. Another session of the same user keeps its own share until the total is spent.
//
// A call spends one unit before it does its work and is refunded the unit when it did not use it (a code that was not
// mailed, an attempt that confirmed). Spending is atomic: the user row is locked while the counters change, so
// concurrent calls cannot overspend either limit. The user's counter is a `verification` row and each session's counter
// is a sibling row that ends with the same window; both end with the user.
import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';

export const ACCOUNT_SETUP_BUDGET_WINDOW_MS = 60 * 60 * 1000;
export const ACCOUNT_SETUP_BUDGET_LIMITS = { send: 10, verify: 10 } as const;
/** What one session may take of the user's limit in a window. */
export const ACCOUNT_SETUP_BUDGET_SESSION_LIMIT = 5;
export type AccountSetupBudget = keyof typeof ACCOUNT_SETUP_BUDGET_LIMITS;

type BudgetDatabase = Pick<PrismaClient, '$transaction'>;

const identifierOf = (budget: AccountSetupBudget, userId: string) => `account-setup-budget:${budget}:${userId}`;
const sessionIdentifierOf = (budget: AccountSetupBudget, userId: string, sessionId: string) => `${identifierOf(budget, userId)}:${sessionId}`;

/** A stored count, or null when the value is not a whole number of at least zero (the caller fails closed). */
function countOf(value: string): number | null {
  return /^\d{1,9}$/.test(value) ? Number.parseInt(value, 10) : null;
}

/** True when the user and this session each had a unit left in the current window; the unit is spent. */
export async function spendAccountSetupBudget(
  db: BudgetDatabase, userId: string, budget: AccountSetupBudget, sessionId: string, now = new Date(),
): Promise<boolean> {
  const identifier = identifierOf(budget, userId);
  const sessionIdentifier = sessionIdentifierOf(budget, userId, sessionId);
  return db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR UPDATE`;
    const row = await tx.verification.findFirst({ where: { identifier, expiresAt: { gt: now } } });
    if (!row) {
      // A new window: the counters of the last one, the user's and every session's, go.
      await tx.verification.deleteMany({ where: { OR: [{ identifier }, { identifier: { startsWith: `${identifier}:` } }] } });
      const expiresAt = new Date(now.getTime() + ACCOUNT_SETUP_BUDGET_WINDOW_MS);
      await tx.verification.create({ data: { id: randomUUID(), identifier, userId, value: '1', expiresAt } });
      await tx.verification.create({ data: { id: randomUUID(), identifier: sessionIdentifier, userId, value: '1', expiresAt } });
      return true;
    }
    const used = countOf(row.value);
    if (used === null || used >= ACCOUNT_SETUP_BUDGET_LIMITS[budget]) return false;
    const sessionRow = await tx.verification.findFirst({ where: { identifier: sessionIdentifier, expiresAt: { gt: now } } });
    const sessionUsed = sessionRow ? countOf(sessionRow.value) : 0;
    if (sessionUsed === null || sessionUsed >= ACCOUNT_SETUP_BUDGET_SESSION_LIMIT) return false;
    await tx.verification.update({ where: { id: row.id }, data: { value: String(used + 1) } });
    if (sessionRow) await tx.verification.update({ where: { id: sessionRow.id }, data: { value: String(sessionUsed + 1) } });
    else await tx.verification.create({ data: { id: randomUUID(), identifier: sessionIdentifier, userId, value: '1', expiresAt: row.expiresAt } });
    return true;
  });
}

/**
 * Refunds a unit that was spent and not used: one from the user's count and one from this session's. A session that
 * holds no unit in the current window (a window that has ended since the spend) refunds nothing; no count goes below
 * zero.
 */
export async function refundAccountSetupBudget(
  db: BudgetDatabase, userId: string, budget: AccountSetupBudget, sessionId: string, now = new Date(),
): Promise<void> {
  const identifier = identifierOf(budget, userId);
  await db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR UPDATE`;
    const row = await tx.verification.findFirst({ where: { identifier, expiresAt: { gt: now } } });
    const sessionRow = await tx.verification.findFirst({
      where: { identifier: sessionIdentifierOf(budget, userId, sessionId), expiresAt: { gt: now } },
    });
    if (!row || !sessionRow) return;
    const used = countOf(row.value);
    const sessionUsed = countOf(sessionRow.value);
    if (used === null || sessionUsed === null || used < 1 || sessionUsed < 1) return;
    await tx.verification.update({ where: { id: row.id }, data: { value: String(used - 1) } });
    await tx.verification.update({ where: { id: sessionRow.id }, data: { value: String(sessionUsed - 1) } });
  });
}
