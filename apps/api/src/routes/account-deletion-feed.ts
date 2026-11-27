import { timingSafeEqual } from 'crypto';
import { Hono, type Context } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { logMetric } from '../log';
import {
  ACCOUNT_DELETION_EVENT_PAGE_DEFAULT,
  ACCOUNT_DELETION_EVENT_PAGE_MAX,
  ACCOUNT_DELETION_FEED_TOKEN_MIN_LENGTH,
} from '../services/account-deletion-event';

// GET /api/internal/account-deletions?after=<id>&limit=<n>: the account-deletion events in id order, for one
// consumer that keeps its own cursor. Read-only, behind its own bearer (OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN, at least
// 32 characters; unset, empty or shorter answers 503). Every response names its environment (the origin of
// BETTER_AUTH_URL) so a consumer can refuse a feed from the wrong deployment. Each event carries every key address of
// the deleted account and nothing else. Addresses, the bearer and the Authorization header are never logged.

const prisma = createPrismaClient();

const MAX_ID = 9_223_372_036_854_775_807n;
const DIGITS = /^[0-9]{1,19}$/;

export type AccountDeletionFeedDatabase = {
  accountDeletionEvent: {
    findMany(args: { where: { id: { gt: bigint } }; orderBy: { id: 'asc' }; take: number }): Promise<Array<{ id: bigint; addresses: string[]; deletedAt: Date }>>;
  };
};

function authorized(authHeader: string | undefined, token: string): boolean {
  if (!authHeader?.startsWith('Bearer ')) return false;
  const expected = Buffer.from(token);
  const provided = Buffer.from(authHeader.slice(7));
  return expected.length === provided.length && timingSafeEqual(expected, provided);
}

function environmentId(): string | null {
  try { return new URL(process.env.BETTER_AUTH_URL ?? '').origin; }
  catch { return null; }
}

/** `null` for anything but a plain non-negative decimal integer within a signed 64-bit id. */
function parseId(value: string | undefined): bigint | null {
  if (value === undefined || !DIGITS.test(value)) return null;
  const id = BigInt(value);
  return id <= MAX_ID ? id : null;
}

function parseLimit(value: string | undefined): number | null {
  if (value === undefined) return ACCOUNT_DELETION_EVENT_PAGE_DEFAULT;
  if (!/^[0-9]{1,9}$/.test(value)) return null;
  const limit = Number(value);
  return limit >= 1 ? Math.min(limit, ACCOUNT_DELETION_EVENT_PAGE_MAX) : null;
}

export const accountDeletionFeedRouter = new Hono();

// Every response is private to the consumer and never cached.
accountDeletionFeedRouter.use('*', async (c, next) => {
  await next();
  c.header('Cache-Control', 'no-store');
});

accountDeletionFeedRouter.all('*', async (c, next) => {
  if (c.req.method !== 'GET') return c.body(null, 405, { Allow: 'GET' });
  await next();
});

accountDeletionFeedRouter.get('/', async (c: Context) => {
  const token = process.env.OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN;
  // Unset, empty or shorter than the minimum: not served, whatever bearer arrives, and checked before any comparison.
  if (!token || token.length < ACCOUNT_DELETION_FEED_TOKEN_MIN_LENGTH) return c.body(null, 503);
  if (!authorized(c.req.header('Authorization'), token)) return c.json({ error: 'Unauthorized' }, 401);
  const environment = environmentId();
  if (!environment) return c.body(null, 503);

  const afterValues = c.req.queries('after') ?? [];
  const limitValues = c.req.queries('limit') ?? [];
  const after = afterValues.length === 0 ? 0n : afterValues.length === 1 ? parseId(afterValues[0]) : null;
  const limit = limitValues.length > 1 ? null : parseLimit(limitValues[0]);
  if (after === null || limit === null) return c.json({ error: 'Invalid after or limit parameter' }, 400);

  let rows: Awaited<ReturnType<AccountDeletionFeedDatabase['accountDeletionEvent']['findMany']>>;
  try {
    rows = await (prisma as unknown as AccountDeletionFeedDatabase).accountDeletionEvent.findMany({
      where: { id: { gt: after } }, orderBy: { id: 'asc' }, take: limit,
    });
  } catch {
    logMetric('error', 'account_deletion_feed_call', { status: 503 });
    return c.body(null, 503);
  }
  logMetric('info', 'account_deletion_feed_call', { status: 200, count: rows.length });
  return c.json({
    environment,
    events: rows.map((row) => ({ id: row.id.toString(), addresses: row.addresses, deletedAt: row.deletedAt.toISOString() })),
    next: rows.length > 0 ? rows[rows.length - 1]!.id.toString() : after.toString(),
  });
});
