import { mayProceedAfterReview, type DeletionPreflight, type DeletionReviewDecision } from './account-deletion-preflight';

export const REVIEW_RECHECK_MS = 6 * 3_600_000;
export const REVIEW_DEADLINE_MS = 7 * 86_400_000;
export const REVIEW_ALERTS = [{ key: 'day-1', offset: 86_400_000 }, { key: 'day-6', offset: 6 * 86_400_000 }] as const;

export function reviewResolution(requestedAt: Date, now: Date, fresh: DeletionPreflight, decision?: DeletionReviewDecision): 'pending' | 'zero' | 'operator' | 'deadline' {
  if (fresh.unavailableHosts.length || fresh.state === 'pending') return 'pending';
  if (mayProceedAfterReview(decision, fresh, now)) return fresh.state === 'ready' ? 'zero' : 'operator';
  if (Number.isFinite(requestedAt.getTime()) && now.getTime() >= requestedAt.getTime() + REVIEW_DEADLINE_MS) return 'deadline';
  return 'pending';
}
