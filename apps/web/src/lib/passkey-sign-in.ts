import { WebAuthnAbortService, browserSupportsWebAuthnAutofill } from '@simplewebauthn/browser';

// better-auth's passkey client turns a failed ceremony into `{ error: { code } }`: a WebAuthnError keeps
// its code, anything else becomes AUTH_CANCELLED. @simplewebauthn/browser raises
// ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY only for a NotAllowedError, which is what the browser raises when
// no passkey matches or the person dismisses the sheet, and ERROR_CEREMONY_ABORTED when a request is
// cancelled by a newer ceremony or an abort signal.
const NOT_ALLOWED_CODE = 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY';
const ABORTED_CODE = 'ERROR_CEREMONY_ABORTED';

function field(error: unknown, key: 'code' | 'name'): unknown {
  return error && typeof error === 'object' && key in error ? (error as Record<string, unknown>)[key] : undefined;
}

/** True when the passkey prompt ended with no passkey used (a returned client error or a thrown DOMException). */
export function isNoPasskeyError(error: unknown): boolean {
  return field(error, 'code') === NOT_ALLOWED_CODE || field(error, 'name') === 'NotAllowedError';
}

/** True when a ceremony was cancelled by the page itself rather than failing. */
export function isCeremonyAborted(error: unknown): boolean {
  return field(error, 'code') === ABORTED_CODE || field(error, 'name') === 'AbortError';
}

export type EnrolmentDecision = 'offer' | 'check' | 'skip';

/**
 * What follows an email-code sign-in:
 * - 'offer': show the passkey offer without asking the account, because the person just found no usable
 *   passkey on this device (native or not, whatever other passkeys the account holds);
 * - 'check': show it only when the account has no passkey (web sign-in);
 * - 'skip': continue; native sheets return to the app and clients without WebAuthn never prompt.
 */
export function enrolmentDecision(input: { passkeysSupported: boolean; native: boolean; afterNoPasskey: boolean }): EnrolmentDecision {
  if (!input.passkeysSupported) return 'skip';
  if (input.afterNoPasskey) return 'offer';
  return input.native ? 'skip' : 'check';
}

/** True when `listUserPasskeys` answered successfully with an empty list. */
export function accountHasNoPasskeys(result: { error?: unknown; data?: unknown } | null | undefined): boolean {
  return Boolean(result) && !result!.error && Array.isArray(result!.data) && result!.data.length === 0;
}

export interface AutofillDeps {
  /** Whether the browser can show passkeys in the input's autofill list. */
  supported: () => Promise<boolean>;
  /**
   * Runs the conditional ceremony and the server verification; resolves to the client result. `onVerify` is
   * called when the assertion is obtained and the server verification is about to be sent, not before.
   */
  signIn: (hooks: { onVerify: () => void }) => Promise<{ error?: unknown } | null | undefined>;
  /** Aborts the pending conditional ceremony. */
  cancel: () => void;
  /** Called once when the autofill sign-in verified and the page is still waiting for it, or a stop adopted it. */
  onSignedIn: () => void;
  /** How often `cancel` is repeated while a stopped request has not settled. */
  retryEveryMs?: number;
  /** The longest a stop waits for the request to settle. */
  boundMs?: number;
}

export interface Autofill {
  /**
   * Ends the request and resolves once it has settled (or the bound passed). Until then `cancel` is
   * repeated, because the ceremony starts only after the options request and would otherwise start late
   * and abort whatever ceremony follows. Calling it again returns the same promise. The cancelling ends
   * when the server starts verifying the assertion, whether that is before or after the stop, because the
   * ceremony has ended: the request waits for the verification, and a verified sign-in is reported to
   * `onSignedIn` once. The promise resolves `true` when it was, and `false` when the request ended with
   * no sign-in (a cancel that aborted the ceremony, a failed verification, or a verification that
   * started or finished after the bound).
   */
  stop: () => Promise<boolean>;
}

let latest: Autofill | null = null;

/**
 * Ends the running conditional request, if any, and resolves when it has settled. A passkey action that
 * starts its own ceremony (the modal sign-in, passkey registration) awaits this first, because the
 * browser keeps one ceremony at a time and a late conditional ceremony would abort the newer one. It
 * resolves `true` when the request had a sign-in in flight and that sign-in verified: the page is signed
 * in and the action must not start a ceremony of its own.
 */
export function supersedePasskeyAutofill(): Promise<boolean> {
  return latest ? latest.stop() : Promise.resolve(false);
}

/**
 * Runs `ceremony` once the autofill request has been superseded, unless that request had a sign-in in
 * flight that verified: that sign-in is the result and `ceremony` does not run.
 */
export async function ceremonyAfterAutofill<T>(ceremony: () => Promise<T>): Promise<{ adopted: true } | { adopted: false; result: T }> {
  if (await supersedePasskeyAutofill()) return { adopted: true };
  return { adopted: false, result: await ceremony() };
}

/**
 * Starts the conditional (autofill) passkey sign-in. Nothing it does is visible to the person: a
 * request that is unsupported, aborted, refused or fails produces no error and no step change; only a
 * verified sign-in calls `onSignedIn`. A stop ends the request: the ceremony is cancelled until the
 * request settles. When the server starts verifying the assertion, whether before or after the stop, the
 * ceremony has ended and the verification is the sign-in: the cancelling stops, the request waits for the
 * verification, and a verified sign-in is reported once while a failed one is not. A stop whose cancel
 * aborts the ceremony ends the request with no sign-in. A request that replaces an older one begins after
 * the older one settled, and does not begin when the older one reported a sign-in.
 */
export function startPasskeyAutofill(deps: AutofillDeps): Autofill {
  const previous = supersedePasskeyAutofill();
  let stopped = false;
  let stopping: Promise<boolean> | undefined;
  let settled = false;
  // The assertion is obtained and the server is verifying it.
  let verifying = false;
  // A stop arrived and the server is verifying, so a verified sign-in is reported; false once the bound passed.
  let adopting = false;
  let boundPassed = false;
  let adopted = false;
  let cancelTimer: ReturnType<typeof setInterval> | undefined;
  // `Promise.withResolvers` is missing from the Safari that the iOS sign-in sheet can run.
  let resolveSettled!: () => void;
  const settledPromise = new Promise<void>((resolve) => {
    resolveSettled = resolve;
  });
  const stopCancelling = () => {
    clearInterval(cancelTimer);
    cancelTimer = undefined;
  };
  const handle: Autofill = {
    stop() {
      // A request that already settled has no ceremony left, and cancelling would hit an unrelated one.
      if (settled) return Promise.resolve(false);
      if (stopping) return stopping;
      stopped = true;
      if (verifying) {
        adopting = true;
      } else {
        deps.cancel();
        cancelTimer = setInterval(deps.cancel, deps.retryEveryMs ?? 100);
      }
      let boundTimer: ReturnType<typeof setTimeout> | undefined;
      const bound = new Promise<void>((resolve) => {
        boundTimer = setTimeout(() => {
          boundPassed = true;
          adopting = false;
          resolve();
        }, deps.boundMs ?? 10_000);
      });
      stopping = Promise.race([settledPromise, bound]).then(() => {
        stopCancelling();
        clearTimeout(boundTimer);
        return adopted;
      });
      return stopping;
    },
  };
  latest = handle;
  void (async () => {
    try {
      if (await previous) {
        // The older request's sign-in is this page's sign-in; a stop of this request reports it.
        adopted = stopped;
        return;
      }
      if (stopped || !(await deps.supported()) || stopped) return;
      const result = await deps.signIn({
        onVerify: () => {
          verifying = true;
          // The assertion exists: cancelling a ceremony that has ended would only hit an unrelated one.
          stopCancelling();
          if (stopped && !boundPassed) adopting = true;
        },
      });
      if (result?.error || (stopped && !adopting)) return;
      adopted = stopped;
      deps.onSignedIn();
    } catch {
      // A rejected or aborted request is never shown.
    } finally {
      settled = true;
      resolveSettled();
      if (latest === handle) latest = null;
    }
  })();
  return handle;
}

export const browserPasskeyAutofill = {
  supported: browserSupportsWebAuthnAutofill,
  cancel: () => WebAuthnAbortService.cancelCeremony(),
};
