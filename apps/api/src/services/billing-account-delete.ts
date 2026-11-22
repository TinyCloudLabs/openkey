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
  const production = process.env.NODE_ENV === 'production' || process.env.TEE_MODE === 'production';
  if (!baseUrl && !secret && !production) return { kind: 'skip' };
  return { kind: 'unavailable' };
}

async function cancelOne(
  deps: Pick<BillingAccountDeleteDeps, 'fetch'>,
  baseUrl: string,
  secret: string,
  address: string,
): Promise<boolean> {
  try {
    const response = await deps.fetch(`${baseUrl}/api/account-delete/${address}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${secret}` },
      redirect: 'error',
      signal: AbortSignal.timeout(BILLING_ACCOUNT_DELETE_TIMEOUT_MS),
    });
    await response.body?.cancel();
    return response.status >= 200 && response.status < 300;
  } catch {
    return false;
  }
}

/**
 * Cancels billing for every `addresses` entry (already lowercase). Counts only are logged; never the
 * addresses themselves. `true` once billing is settled for all of them: each call succeeded, there were
 * none, or the environment skips billing. `false` refuses the deletion before anything is deleted.
 */
export async function cancelBillingForAccountDelete(
  addresses: readonly string[],
  deps: BillingAccountDeleteDeps = defaultDeps,
): Promise<boolean> {
  const plan = billingAccountDeletePlan();
  if (plan.kind === 'skip') {
    if (addresses.length > 0) logAccountDeleteBilling('skipped_unconfigured', { addresses: addresses.length });
    return true;
  }
  if (plan.kind === 'unavailable') {
    logAccountDeleteBilling('unavailable', { addresses: addresses.length, failed: 0 });
    return false;
  }
  let failed = 0;
  for (const address of addresses) {
    if (!await cancelOne(deps, plan.baseUrl, plan.secret, address)) failed += 1;
  }
  if (failed > 0) {
    logAccountDeleteBilling('unavailable', { addresses: addresses.length, failed });
    return false;
  }
  if (addresses.length > 0) logAccountDeleteBilling('settled', { addresses: addresses.length });
  return true;
}
