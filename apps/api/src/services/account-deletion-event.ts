import { createHash } from 'node:crypto';
import type { Prisma } from '@openkey/db';

// The account-deletion event feed (GET /api/internal/account-deletions). One row per deleted account, written in the
// deletion's own transaction; a consumer reads the rows in id order and keeps its own cursor. OpenKey keeps no
// delivery state. Configuration: the feed reads OPENKEY_ACCOUNT_DELETIONS_READ_TOKEN (a read-only bearer; the feed
// answers 503 while it is unset) and names its environment by the origin of BETTER_AUTH_URL.

/** Rows older than this are deleted by the retention sweep: they hold addresses. */
export const ACCOUNT_DELETION_EVENT_RETENTION_DAYS = 60;
export const ACCOUNT_DELETION_EVENT_RETENTION_MS = ACCOUNT_DELETION_EVENT_RETENTION_DAYS * 86_400_000;
/** How often the retention sweep runs, and how long after boot the first pass waits. */
export const ACCOUNT_DELETION_EVENT_SWEEP_INTERVAL_MS = 6 * 3_600_000;
export const ACCOUNT_DELETION_EVENT_SWEEP_FIRST_PASS_DELAY_MS = 60_000;
export const ACCOUNT_DELETION_EVENT_PAGE_DEFAULT = 100;
export const ACCOUNT_DELETION_EVENT_PAGE_MAX = 100;

/**
 * Transaction-scoped advisory lock taken immediately before an event row is inserted. A consumer keeps the largest id
 * it has read; with a plain auto-increment id, two deletions can commit out of id order (the lower id commits second)
 * and the consumer would skip the later-committing lower id for good. Taking this lock first means the id is assigned
 * after the lock is held and the lock is released only at commit, so a later deletion cannot get its id, let alone
 * commit, before an earlier one has committed: ids commit in order. Deletions are rare, so serialising them costs
 * nothing that matters. The lock is the last cross-account resource a deletion takes.
 */
export const ACCOUNT_DELETION_EVENT_LOCK_ID = BigInt.asIntN(
  64,
  BigInt(`0x${createHash('sha256').update('account-deletion-event\0insert-order').digest('hex').slice(0, 16)}`),
);

export type AccountDeletionEventTransaction = Pick<Prisma.TransactionClient, 'ethereumKey' | 'accountDeletionEvent' | '$queryRaw'>;

/**
 * Records that `userId`'s account is being deleted: every `EthereumKey.address` the user holds (managed, archived and
 * external, no filter), exactly as stored. Call inside the deletion's transaction, under the user-row lock and before
 * the keys are deleted; a refused or rolled-back deletion then leaves no event. Stores no user id, email or name.
 * A user with no key address inserts nothing: an event with an empty address list would name nobody.
 */
export async function recordAccountDeletionEvent(transaction: AccountDeletionEventTransaction, userId: string): Promise<void> {
  const keys = await transaction.ethereumKey.findMany({ where: { userId }, select: { address: true }, orderBy: [{ keyIndex: 'asc' }, { id: 'asc' }] });
  if (keys.length === 0) return;
  await transaction.$queryRaw`SELECT pg_advisory_xact_lock(${ACCOUNT_DELETION_EVENT_LOCK_ID})::text`;
  await transaction.accountDeletionEvent.create({ data: { addresses: keys.map((key) => key.address), deletedAt: new Date() } });
}
