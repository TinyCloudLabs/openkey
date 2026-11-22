// Telling billing an account is going away (TC-3903). `POST /api/account/delete` must cancel every
// subscription and billing record before the Postgres rows go; otherwise a deleted user keeps paying.
// The billing API owns Stripe, so deletion asks it once per ethereum address of the account:
//
//   POST {BILLING_API_URL}/api/account-delete/<lowercase 0x address>
//   Authorization: Bearer <ACCOUNT_DELETE_SERVICE_SECRET>
//
// 2xx answers `{ ok: true, deleted: {...}, stripe: { canceled, deleted } }` and the call is idempotent:
// a repeat returns 200 with zero counts, which makes the delete safe to retry after a crash between the
// billing calls and the commit. Non-2xx answers `{ ok: false, error }`. Any call that is not 2xx, that
// times out (10s), or that cannot be sent because the configuration is missing refuses the deletion with
// 503 `billing_unavailable` and deletes nothing.
//
// Configuration: BILLING_API_URL and ACCOUNT_DELETE_SERVICE_SECRET, both required to call. When neither
// is set, behaviour depends on the environment, matching the email-OTP delivery convention
// (email-otp-delivery.ts): production (NODE_ENV or TEE_MODE `production`) fails closed with the 503 so a
// deploy that forgot billing can never silently keep subscriptions; development and test skip the calls
// entirely (there is no billing to cancel locally). One variable set without the other is a
// misconfiguration, not "unset", and fails closed everywhere.
import { logAccountDeleteBilling } from '../log';

export const BILLING_ACCOUNT_DELETE_TIMEOUT_MS = 10_000;

export interface BillingAccountDeleteDeps {
  fetch: (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => Promise<Response>;
}

const defaultDeps: BillingAccountDeleteDeps = {
  // Resolved per call: tests substitute globalThis.fetch.
  fetch: (...args) => fetch(...args),
};

export type BillingAccountDeletePlan =
  | { kind: 'call'; baseUrl: string; secret: string }
  | { kind: 'skip' }
  | { kind: 'unavailable' };

/**
 * What a deletion must do about billing, from the environment alone. Read per request so a test or a
 * config reload sees the current values.
 */
export function billingAccountDeletePlan(env: NodeJS.ProcessEnv = process.env): BillingAccountDeletePlan {
  const baseUrl = env.BILLING_API_URL?.trim();
  const secret = env.ACCOUNT_DELETE_SERVICE_SECRET?.trim();
  if (baseUrl && secret) return { kind: 'call', baseUrl: baseUrl.replace(/\/+$/, ''), secret };
  // The isDev formula used across the API: anything but NODE_ENV/TEE_MODE production.
  const production = env.NODE_ENV === 'production' || env.TEE_MODE === 'production';
  if (!baseUrl && !secret && !production) return { kind: 'skip' };
  return { kind: 'unavailable' };
}

interface CancelOneResult {
  ok: boolean;
  /** stripe.canceled from a 2xx answer; missing or invalid counts as 0. */
  canceled: number;
}

async function cancelOne(
  deps: Pick<BillingAccountDeleteDeps, 'fetch'>,
  baseUrl: string,
  secret: string,
  address: string,
): Promise<CancelOneResult> {
  try {
    const response = await deps.fetch(`${baseUrl}/api/account-delete/${address}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${secret}` },
      redirect: 'error',
      signal: AbortSignal.timeout(BILLING_ACCOUNT_DELETE_TIMEOUT_MS),
    });
    const ok = response.status >= 200 && response.status < 300;
    let canceled = 0;
    if (ok) {
      const body: unknown = await response.json().catch(() => null);
      if (typeof body === 'object' && body !== null && 'stripe' in body) {
        const stripe = body.stripe;
        if (typeof stripe === 'object' && stripe !== null && 'canceled' in stripe && typeof stripe.canceled === 'number') {
          canceled = stripe.canceled;
        }
      }
    } else {
      await response.body?.cancel();
    }
    return { ok, canceled };
  } catch {
    return { ok: false, canceled: 0 };
  }
}

export interface AccountDeleteBillingOutcome {
  /** false refuses the deletion: billing could not be settled — non-2xx, timeout or missing config. */
  ok: boolean;
  /** Billing was called for every address and every call returned 2xx; false only for the dev/test skip. */
  billingOk: boolean;
  /** Any billing answer reported stripe.canceled > 0. */
  hadSubscription: boolean;
}

/**
 * Cancels billing for every `addresses` entry (already lowercase). Counts only are logged; never the
 * addresses themselves. `ok` once billing is settled for all of them: each call succeeded, there were
 * none, or the environment skips billing — the outcome fields feed the deletion's audit row.
 */
export async function cancelBillingForAccountDelete(
  addresses: readonly string[],
  deps: BillingAccountDeleteDeps = defaultDeps,
): Promise<AccountDeleteBillingOutcome> {
  const plan = billingAccountDeletePlan();
  if (plan.kind === 'skip') {
    if (addresses.length > 0) logAccountDeleteBilling('skipped_unconfigured', { addresses: addresses.length });
    return { ok: true, billingOk: false, hadSubscription: false };
  }
  if (plan.kind === 'unavailable') {
    logAccountDeleteBilling('unavailable', { addresses: addresses.length, failed: 0 });
    return { ok: false, billingOk: false, hadSubscription: false };
  }
  let failed = 0;
  let hadSubscription = false;
  for (const address of addresses) {
    const result = await cancelOne(deps, plan.baseUrl, plan.secret, address);
    if (!result.ok) failed += 1;
    if (result.canceled > 0) hadSubscription = true;
  }
  if (failed > 0) {
    logAccountDeleteBilling('unavailable', { addresses: addresses.length, failed });
    return { ok: false, billingOk: false, hadSubscription };
  }
  if (addresses.length > 0) logAccountDeleteBilling('settled', { addresses: addresses.length });
  return { ok: true, billingOk: true, hadSubscription };
}
