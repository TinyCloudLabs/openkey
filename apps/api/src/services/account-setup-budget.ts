// What one account may ask of the account setup routes in an hour, across all its setup requests and sessions.
//
// The email code and the step-up attempts are limited per request and session (account-setup-step-up.ts: three wrong
// guesses a code), and a request or a session can be replaced. These budgets are keyed by the user alone, so a new
// request or a new session does not reset them:
//   send    codes mailed to the owner
//   verify  step-up attempts (a code or a passkey assertion) that did not confirm
//
// A call spends one unit before it does its work and is refunded the unit when it did not use it (a code that was not
// mailed, an attempt that confirmed). Spending is atomic: the user row is locked while the counter changes, so
// concurrent calls cannot overspend. The counter is a `verification` row that ends with the user.
import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';

export const ACCOUNT_SETUP_BUDGET_WINDOW_MS = 60 * 60 * 1000;
export const ACCOUNT_SETUP_BUDGET_LIMITS = { send: 10, verify: 10 } as const;
export type AccountSetupBudget = keyof typeof ACCOUNT_SETUP_BUDGET_LIMITS;

type BudgetDatabase = Pick<PrismaClient, '$transaction'>;

const identifierOf = (budget: AccountSetupBudget, userId: string) => `account-setup-budget:${budget}:${userId}`;

/** True when the user had a unit left in the current window; the unit is spent. */
export async function spendAccountSetupBudget(
  db: BudgetDatabase, userId: string, budget: AccountSetupBudget, now = new Date(),
): Promise<boolean> {
  const identifier = identifierOf(budget, userId);
  return db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR UPDATE`;
    const row = await tx.verification.findFirst({ where: { identifier, expiresAt: { gt: now } } });
    if (!row) {
      await tx.verification.deleteMany({ where: { identifier } });
      await tx.verification.create({ data: {
        id: randomUUID(), identifier, userId, value: '1', expiresAt: new Date(now.getTime() + ACCOUNT_SETUP_BUDGET_WINDOW_MS),
      } });
      return true;
    }
    const used = Number.parseInt(row.value, 10);
    if (!(used < ACCOUNT_SETUP_BUDGET_LIMITS[budget])) return false;
    await tx.verification.update({ where: { id: row.id }, data: { value: String(used + 1) } });
    return true;
  });
}

/** Refunds a unit that was spent and not used. */
export async function refundAccountSetupBudget(
  db: BudgetDatabase, userId: string, budget: AccountSetupBudget, now = new Date(),
): Promise<void> {
  const identifier = identifierOf(budget, userId);
  await db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR UPDATE`;
    const row = await tx.verification.findFirst({ where: { identifier, expiresAt: { gt: now } } });
    const used = row ? Number.parseInt(row.value, 10) : 0;
    if (row && used > 0) await tx.verification.update({ where: { id: row.id }, data: { value: String(used - 1) } });
  });
}
