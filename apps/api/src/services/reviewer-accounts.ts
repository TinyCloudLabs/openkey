import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, timingSafeEqual } from 'node:crypto';
import type { PrismaClient, Prisma } from '@openkey/db';
import { logReviewer } from '../log';

export const REVIEWER_MAX_SECONDS = 3600;
export const REVIEWER_STORES = ['openai', 'google', 'apple'] as const;
export type ReviewerStore = typeof REVIEWER_STORES[number];
export type ReviewerBinding = Prisma.ReviewerAccountGetPayload<{ include: { user: true } }>;
type Authority = { userId: string; epoch: number; store: ReviewerStore; sessionId?: string; deadline?: number };
type RequestState = { authority?: Authority };
export const reviewerRequest = new AsyncLocalStorage<RequestState>();

const verifiers = new Map<string, { digest: Buffer; epoch: number }>();
const failures = new Map<string, number>();

export function credentialDigest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

export function adminCredentialMatches(provided: string, expected: string): boolean {
  return timingSafeEqual(credentialDigest(provided), credentialDigest(expected));
}

export function reviewerCodeFormat(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value)
    && Buffer.from(value, 'base64url').length === 32
    && Buffer.from(value, 'base64url').toString('base64url') === value;
}

export function normalizedReviewerEmail(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

export async function reviewerForEmail(database: PrismaClient, email: unknown) {
  return database.reviewerAccount.findUnique({
    where: { email: normalizedReviewerEmail(email) }, include: { user: true },
  });
}

export async function reviewerForUser(database: PrismaClient, userId: string) {
  return database.reviewerAccount.findUnique({ where: { userId }, include: { user: true } });
}

export function reviewerActive(binding: ReviewerBinding | null, epoch?: number | null): binding is ReviewerBinding {
  if (!binding?.user || binding.store === 'apple' || binding.user.lockedAt || binding.user.reviewerHoldAt) return false;
  const installed = verifiers.get(binding.store);
  return installed?.epoch === binding.installEpoch && (epoch === undefined || epoch === binding.installEpoch);
}

export function reviewerCodeMatches(binding: ReviewerBinding | null, code: unknown): boolean {
  const provided = credentialDigest(typeof code === 'string' && code.length <= 128 ? code : '');
  const installed = binding ? verifiers.get(binding.store) : undefined;
  const matched = timingSafeEqual(provided, installed?.digest ?? Buffer.alloc(32));
  return matched && reviewerCodeFormat(code) && reviewerActive(binding);
}

export async function reviewerFailure(binding: ReviewerBinding | null): Promise<void> {
  const store = binding?.store ?? 'unknown';
  const attempts = Math.min((failures.get(store) ?? 0) + 1, 4);
  failures.set(store, attempts);
  await new Promise((resolve) => setTimeout(resolve, Math.min(250 * 2 ** (attempts - 1), 2000)));
}

export function captureReviewer(binding: ReviewerBinding, sessionId?: string, deadline?: number): void {
  const state = reviewerRequest.getStore();
  if (!state || !reviewerActive(binding)) throw new Error('Reviewer authentication refused');
  state.authority = { userId: binding.userId!, epoch: binding.installEpoch, store: binding.store as ReviewerStore, sessionId, deadline };
}

export function capturedReviewer(): Authority | undefined {
  return reviewerRequest.getStore()?.authority;
}

/** Binding lock precedes the user and consent locks for every admin mutation. */
export async function lockReviewer(transaction: Prisma.TransactionClient, store: string) {
  await transaction.$queryRaw`SELECT store FROM reviewer_account WHERE store = ${store} FOR UPDATE`;
  return transaction.reviewerAccount.findUniqueOrThrow({ where: { store }, include: { user: true } });
}

export async function holdReviewer(transaction: Prisma.TransactionClient, binding: ReviewerBinding) {
  verifiers.delete(binding.store);
  if (binding.userId) {
    const userId = binding.userId;
    await transaction.user.update({ where: { id: userId }, data: { reviewerHoldAt: new Date() } });
    // Removing consent advances the existing native consent generation via its trigger.
    await transaction.oauthConsent.deleteMany({ where: { userId } });
    await transaction.tinyCloudNativeGrant.deleteMany({ where: { userId } });
    await transaction.tinyCloudNativeRequest.deleteMany({ where: { userId } });
    await transaction.oauthAccessToken.deleteMany({ where: { userId } });
    await transaction.oauthRefreshToken.deleteMany({ where: { userId } });
    await transaction.verification.deleteMany({ where: { OR: [
      { userId },
      { value: { contains: '"userId":' + JSON.stringify(userId) } },
    ] } });
    await transaction.session.deleteMany({ where: { userId } });
  }
  return transaction.reviewerAccount.update({
    where: { store: binding.store }, data: { installEpoch: { increment: 1 }, grantSessionId: null, readyAt: null },
    include: { user: true },
  });
}

export async function unsetReviewer(database: PrismaClient, store: string) {
  verifiers.delete(store);
  const binding = await database.$transaction(async (transaction) => holdReviewer(transaction, await lockReviewer(transaction, store)));
  logReviewer('reviewer_admin', 'unset', store);
  return binding;
}

export async function installReviewer(database: PrismaClient, store: string, code: unknown) {
  if (store === 'apple' || !reviewerCodeFormat(code)) throw new Error('Invalid reviewer installation');
  const digest = credentialDigest(code);
  verifiers.delete(store);
  await database.$transaction(async (transaction) => {
    const before = await lockReviewer(transaction, store);
    if (!before.user || before.user.lockedAt || !before.seededAt || !before.clientId || !before.redirectUri
      || !before.resource || !before.callbackUri || !before.nodeHost || !before.keyId || !before.spaceId) {
      throw new Error('Reviewer account is not ready');
    }
    const binding = await holdReviewer(transaction, before);
    await transaction.user.update({ where: { id: binding.userId! }, data: { reviewerHoldAt: null } });
    // Process memory is installed before commit while competing mutations wait on the binding lock.
    verifiers.set(store, { digest, epoch: binding.installEpoch });
  }).catch((error) => {
    verifiers.delete(store);
    throw error;
  });
  failures.delete(store);
  logReviewer('reviewer_admin', 'installed', store);
}

export async function initializeReviewers(database: PrismaClient) {
  verifiers.clear();
  await database.$transaction(async (transaction) => {
    for (const store of REVIEWER_STORES) {
      const binding = await transaction.reviewerAccount.findUnique({ where: { store } });
      if (binding) await holdReviewer(transaction, await lockReviewer(transaction, store));
    }
  });
  logReviewer('reviewer_admin', 'boot_hold', 'all');
}

export function reviewerStatus(binding: ReviewerBinding) {
  return { store: binding.store, set: reviewerActive(binding), ready: Boolean(binding.readyAt), held: binding.user?.reviewerHoldAt !== null || !binding.user };
}

export async function pinReviewerAudience(database: PrismaClient, store: string, sessionDid: string | null) {
  if (store === 'apple' || (sessionDid !== null && !/^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$/.test(sessionDid))) {
    throw new Error('Reviewer audience refused');
  }
  verifiers.delete(store);
  await database.$transaction(async (transaction) => {
    const binding = await holdReviewer(transaction, await lockReviewer(transaction, store));
    await transaction.reviewerAccount.update({ where: { store: binding.store }, data: { sessionDid } });
  });
  logReviewer('reviewer_admin', 'audience_pinned', store);
}
