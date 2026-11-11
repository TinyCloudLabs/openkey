import { HTTPException } from 'hono/http-exception';
import type { Prisma, PrismaClient } from '@openkey/db';
import { APPLE_REVIEW_CLIENT_ID, appleReviewEnabled, reviewerHomePermissions } from './reviewer-apple-policy';
import { capturedReviewer, lockReviewer, normalizedReviewerEmail, reviewerActive, reviewerForUser, REVIEWER_MAX_SECONDS } from './reviewer-accounts';
import { authoritativeQuery, matchesAuthoritativeQuery } from './native-delegation/par';
import type { ReviewerBinding } from './reviewer-accounts';

function refused(): never { throw new HTTPException(403, { message: 'Reviewer native request refused' }); }
type Database = PrismaClient | Prisma.TransactionClient;
type NativeRequest = Prisma.TinyCloudNativeRequestGetPayload<Record<string, never>>;

export async function reviewerNativeQuery(database: Database, binding: ReviewerBinding, query: URLSearchParams, allowApproved = false): Promise<boolean> {
  if (!appleReviewEnabled() || binding.store !== 'apple' || binding.clientId !== APPLE_REVIEW_CLIENT_ID) return false;
  const id = query.get('tinycloud_request');
  if (!id || query.has('resource')) return false;
  const row = await database.tinyCloudNativeRequest.findUnique({ where: { id } });
  if (!row) return false;
  const expected = authoritativeQuery(row);
  // Better Auth removes login_hint once the user has signed in. The hint
  // remains checked against the binding in the persisted PAR row; only an
  // already authenticated reviewer may resume without that display hint.
  if (allowApproved && !query.has('login_hint')) expected.delete('login_hint');
  return Boolean(row && (row.status === 'RESOLVED' || (allowApproved && row.status === 'APPROVED')) && row.expiresAt > new Date()
    && row.clientId === binding.clientId && row.redirectUri === binding.redirectUri
    && row.loginMethod === 'email' && (!row.loginHint || normalizedReviewerEmail(row.loginHint) === binding.email)
    && reviewerHomePermissions(row.requestedPermissions)
    && matchesAuthoritativeQuery(query, expected));
}

// Invoke before consent/generation/request locks, for a consistent lock order.
export async function lockNativeReviewer(tx: Prisma.TransactionClient, userId: string) {
  const binding = await reviewerForUser(tx as PrismaClient, userId);
  return binding ? lockReviewer(tx, binding.store) : null;
}

export async function nativeReviewerAuthority(database: Database, userId: string, row: NativeRequest, binding?: ReviewerBinding | null) {
  const reviewer = binding === undefined ? await reviewerForUser(database as PrismaClient, userId) : binding;
  if (!reviewer) return null;
  if (reviewer.store !== 'apple' || !appleReviewEnabled() || !reviewerActive(reviewer)
    || row.clientId !== APPLE_REVIEW_CLIENT_ID || row.clientId !== reviewer.clientId
    || row.redirectUri !== reviewer.redirectUri || !reviewerHomePermissions(row.requestedPermissions)) refused();
  const captured = capturedReviewer();
  const sessionId = row.reviewerSessionId ?? captured?.sessionId;
  if (!sessionId || (row.reviewerEpoch !== null && row.reviewerEpoch !== reviewer.installEpoch)) refused();
  const session = await database.session.findUnique({ where: { id: sessionId } });
  const deadline = session ? session.createdAt.getTime() + REVIEWER_MAX_SECONDS * 1000 : 0;
  if (!session || session.userId !== userId || session.reviewerEpoch !== reviewer.installEpoch
    || session.expiresAt <= new Date() || deadline <= Date.now()
    || (row.reviewerDeadline && row.reviewerDeadline.getTime() !== deadline)) refused();
  return { binding: reviewer, sessionId, deadline, ttlSeconds: Math.floor((deadline - Date.now()) / 1000) };
}
