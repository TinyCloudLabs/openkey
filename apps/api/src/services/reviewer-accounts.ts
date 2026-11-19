import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, timingSafeEqual } from 'node:crypto';
import { Prisma, type PrismaClient } from '@openkey/db';
import { enabledNativeDelegation } from './native-delegation/policy';
import { appleReviewEnabled, APPLE_REVIEW_CLIENT_ID } from './reviewer-apple-policy';
import { log, logReviewer } from '../log';
import { recordTermsAcceptance, termsRelease } from './terms';

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
  if (!binding?.user || (binding.store === 'apple' && !appleReviewEnabled()) || binding.user.lockedAt || binding.user.reviewerHoldAt) return false;
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

/**
 * Process memory follows the database: callers apply it only after their transaction has
 * committed, so a change that fails leaves the stored and the in-memory state as they were and
 * a restart cannot bring back something the caller was told is gone. It never replaces the
 * verifier of a later epoch. Without a digest the store's verifier is dropped.
 */
export function settleReviewerVerifier(store: string, epoch: number, digest?: Buffer): void {
  if ((verifiers.get(store)?.epoch ?? -1) > epoch) return;
  if (digest) verifiers.set(store, { digest, epoch });
  else verifiers.delete(store);
}

/** Database side of a hold only. The caller settles the verifier once this has committed. */
export async function holdReviewer(transaction: Prisma.TransactionClient, binding: ReviewerBinding) {
  if (binding.userId) {
    const userId = binding.userId;
    // Binding FOR UPDATE already blocks new reviewer authority. Remove native
    // rows before consent revocation updates them: epoch triggers deliberately
    // reject any UPDATE once the user is held.
    await transaction.tinyCloudNativeGrant.deleteMany({ where: { userId } });
    await transaction.tinyCloudNativeRequest.deleteMany({ where: { userId } });
    await transaction.oauthConsent.deleteMany({ where: { userId } });
    await transaction.user.update({ where: { id: userId }, data: { reviewerHoldAt: new Date() } });
    await transaction.oauthAccessToken.deleteMany({ where: { userId } });
    await transaction.oauthRefreshToken.deleteMany({ where: { userId } });
    await transaction.verification.deleteMany({ where: { OR: [
      { userId },
      { value: { contains: '"userId":' + JSON.stringify(userId) } },
    ] } });
    await transaction.session.deleteMany({ where: { userId } });
  }
  // Every hold (unset, reset, audience change, boot hold) also forgets the persisted code digest.
  return transaction.reviewerAccount.update({
    where: { store: binding.store },
    data: { installEpoch: { increment: 1 }, grantSessionId: null, readyAt: null, codeDigest: null, seedRun: Prisma.DbNull },
    include: { user: true },
  });
}

export async function unsetReviewer(database: PrismaClient, store: string) {
  const binding = await database.$transaction(async (transaction) => holdReviewer(transaction, await lockReviewer(transaction, store)));
  settleReviewerVerifier(store, binding.installEpoch);
  logReviewer('reviewer_admin', 'unset', store);
  return binding;
}

export async function installReviewer(database: PrismaClient, store: string, code: unknown) {
  if ((store === 'apple' && !appleReviewEnabled()) || !reviewerCodeFormat(code)) throw new Error('Invalid reviewer installation');
  const digest = credentialDigest(code);
  const epoch = await database.$transaction(async (transaction) => {
    const before = await lockReviewer(transaction, store);
    if (!before.user || before.user.lockedAt || !before.seededAt || !before.clientId || !before.redirectUri
      || !before.nodeHost || !before.keyId || !before.spaceId
      || (store === 'apple' ? before.clientId !== APPLE_REVIEW_CLIENT_ID : !before.resource || !before.callbackUri)) {
      throw new Error('Reviewer account is not ready');
    }
    if (store === 'apple') {
      const [key, hosted, client] = await Promise.all([
        transaction.ethereumKey.findFirst({ where: { custody: 'PERSONAL', id: before.keyId!, userId: before.userId!, isCanonicalTinyCloud: true, archivedAt: null } }),
        transaction.tinyCloudBootstrapState.findFirst({ where: { keyId: before.keyId!, tinycloudHost: before.nodeHost!, chainId: 1, status: 'complete' } }),
        transaction.oauthClient.findUnique({ where: { clientId: before.clientId! } }),
      ]);
      if (!key?.sealedBlob || !hosted || !client || !client.redirectUris.includes(before.redirectUri!)
        || enabledNativeDelegation(client)?.tinycloudHost !== before.nodeHost) throw new Error('Reviewer native fixture is not ready');
    }
    const binding = await holdReviewer(transaction, before);
    await transaction.user.update({ where: { id: binding.userId! }, data: { reviewerHoldAt: null } });
    // Only the SHA-256 digest of the 32-byte code is stored, so an API restart can restore it.
    await transaction.reviewerAccount.update({ where: { store }, data: { codeDigest: digest.toString('hex') } });
    return binding.installEpoch;
  });
  // Until this line the previous verifier is still in memory at an older epoch, which no check accepts.
  settleReviewerVerifier(store, epoch, digest);
  failures.delete(store);
  logReviewer('reviewer_admin', 'installed', store);
}

/**
 * Runs once per API start. A binding whose installed code left a digest, and whose user is
 * neither held nor locked, gets its verifier back at the same epoch, so its live sessions and
 * the code keep working across a restart. Every other binding is held as before.
 */
export async function initializeReviewers(database: PrismaClient) {
  verifiers.clear();
  const restored = new Map<string, { digest: Buffer; epoch: number }>();
  await database.$transaction(async (transaction) => {
    // API start must not wait on a row lock someone else holds (an open psql transaction, another
    // process mid admin call). After two seconds the statement fails and boot fails closed.
    await transaction.$executeRaw`SET LOCAL lock_timeout = '2s'`;
    for (const store of REVIEWER_STORES) {
      if (!await transaction.reviewerAccount.findUnique({ where: { store } })) continue;
      const binding = await lockReviewer(transaction, store);
      if (store !== 'apple' && binding.codeDigest && /^[0-9a-f]{64}$/.test(binding.codeDigest)
        && binding.user && !binding.user.lockedAt && !binding.user.reviewerHoldAt) {
        restored.set(store, { digest: Buffer.from(binding.codeDigest, 'hex'), epoch: binding.installEpoch });
      } else {
        await holdReviewer(transaction, binding);
      }
    }
  });
  await seedReviewerTerms(database);
  for (const store of REVIEWER_STORES) {
    const verifier = restored.get(store);
    if (verifier) verifiers.set(store, verifier);
    logReviewer('reviewer_admin', verifier ? 'boot_restored' : 'boot_hold', store);
  }
}

/** A failed boot hold must not stop the API: with no verifier installed every reviewer stays refused. */
export async function initializeReviewersAtBoot(database: PrismaClient) {
  try {
    await initializeReviewers(database);
  } catch {
    verifiers.clear();
    log('error', 'reviewer_boot_failed');
  }
}

/**
 * TC-3232: app-review accounts have no owner to accept the Terms, and store review would stop at the screen.
 * Each bound account is recorded as accepting the current version, marked as seeded. Runs at every start, so
 * a new version is seeded when it is deployed.
 */
export async function seedReviewerTerms(database: Pick<PrismaClient, 'reviewerAccount' | 'termsAcceptance'>) {
  const release = termsRelease();
  if (!release) return;
  const bindings = await database.reviewerAccount.findMany({ where: { userId: { not: null } }, select: { userId: true } });
  for (const { userId } of bindings) await recordTermsAcceptance(database, userId!, release, 'reviewer_seed');
}

export function reviewerStatus(binding: ReviewerBinding) {
  return { store: binding.store, set: reviewerActive(binding), ready: Boolean(binding.readyAt), held: binding.user?.reviewerHoldAt !== null || !binding.user };
}

export async function pinReviewerAudience(database: PrismaClient, store: string, sessionDid: string | null) {
  if (store === 'apple' || (sessionDid !== null && !/^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$/.test(sessionDid))) {
    throw new Error('Reviewer audience refused');
  }
  const epoch = await database.$transaction(async (transaction) => {
    const binding = await holdReviewer(transaction, await lockReviewer(transaction, store));
    await transaction.reviewerAccount.update({ where: { store: binding.store }, data: { sessionDid } });
    return binding.installEpoch;
  });
  settleReviewerVerifier(store, epoch);
  logReviewer('reviewer_admin', 'audience_pinned', store);
}
