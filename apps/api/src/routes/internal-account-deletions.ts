import { timingSafeEqual } from 'crypto';
import { Hono } from 'hono';
import { getPrisma } from '@openkey/db';
import { logMetric } from '../log';

// TC-3353: the account-deletion receipts, for a server-side caller holding INTERNAL_DELETION_EXPORT_TOKEN.
// A response row is {receiptId, deletedAt, ownerDigests} and nothing else.
export const ACCOUNT_DELETIONS_PAGE_SIZE = 1000;

// RFC 3339 date-time with a mandatory offset.
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

type Receipt = { id: string; deletedAt: Date; ownerDigests: string[] };
export type AccountDeletionsDatabase = {
  accountDeletionReceipt: { findMany(options: Record<string, unknown>): Promise<Receipt[]> };
};

function authorized(authHeader: string | undefined): boolean {
  const token = process.env.INTERNAL_DELETION_EXPORT_TOKEN;
  if (!token) return false;
  if (!authHeader?.startsWith('Bearer ')) return false;

  const expectedBytes = Buffer.from(token);
  const providedBytes = Buffer.from(authHeader.slice(7));
  if (expectedBytes.length !== providedBytes.length) return false;
  return timingSafeEqual(expectedBytes, providedBytes);
}

export function createInternalAccountDeletionsRouter(getDatabase: () => AccountDeletionsDatabase) {
  const router = new Hono();

  router.get('/', async (c) => {
    if (!process.env.INTERNAL_DELETION_EXPORT_TOKEN) return c.json({ error: 'Not configured' }, 503);
    if (!authorized(c.req.header('Authorization'))) return c.json({ error: 'Unauthorized' }, 401);

    const sinceParam = c.req.query('since');
    let since: Date | undefined;
    if (sinceParam !== undefined) {
      since = RFC3339.test(sinceParam) ? new Date(sinceParam) : undefined;
      if (since === undefined || Number.isNaN(since.getTime())) return c.json({ error: 'Invalid since' }, 400);
    }

    // The cursor is (deletedAt, id). With `since` alone: receipts strictly after that time. With `since` and
    // `after_id`: receipts strictly after that (deletedAt, id) pair, so a page that cuts between receipts sharing
    // a deletedAt loses none. A caller continues from the last row it received; a full page means more may follow.
    const afterId = c.req.query('after_id');
    if (afterId !== undefined && (since === undefined || afterId.length === 0 || afterId.length > 64)) {
      return c.json({ error: 'Invalid after_id' }, 400);
    }
    const where = since === undefined
      ? {}
      : afterId === undefined
        ? { deletedAt: { gt: since } }
        : { OR: [{ deletedAt: { gt: since } }, { deletedAt: since, id: { gt: afterId } }] };
    const receipts = await getDatabase().accountDeletionReceipt.findMany({
      where,
      orderBy: [{ deletedAt: 'asc' }, { id: 'asc' }],
      take: ACCOUNT_DELETIONS_PAGE_SIZE,
    });
    logMetric('info', 'account_deletion_export', { status: 200, count: receipts.length });
    c.header('Cache-Control', 'no-store');
    return c.json(receipts.map((receipt) => ({
      receiptId: receipt.id,
      deletedAt: receipt.deletedAt.toISOString(),
      ownerDigests: receipt.ownerDigests,
    })));
  });

  return router;
}

export const internalAccountDeletionsRouter = createInternalAccountDeletionsRouter(
  () => getPrisma() as unknown as AccountDeletionsDatabase,
);
