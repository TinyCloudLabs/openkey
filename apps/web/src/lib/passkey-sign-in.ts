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
  /** Runs the conditional ceremony and the server verification; resolves to the client result. */
  signIn: () => Promise<{ error?: unknown } | null | undefined>;
  /** Aborts the pending conditional ceremony. */
  cancel: () => void;
  /** Called once when the autofill sign-in verified and the page is still waiting for it. */
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
   * and abort whatever ceremony follows. Calling it again returns the same promise.
   */
  stop: () => Promise<void>;
}

let latest: Autofill | null = null;

/**
 * Ends the running conditional request, if any, and resolves when it has settled. A passkey action that
 * starts its own ceremony (the modal sign-in, passkey registration) awaits this first, because the
 * browser keeps one ceremony at a time and a late conditional ceremony would abort the newer one.
 */
export function supersedePasskeyAutofill(): Promise<void> {
  return latest ? latest.stop() : Promise.resolve();
}

/**
 * Starts the conditional (autofill) passkey sign-in. Nothing it does is visible to the person: a
 * request that is unsupported, aborted, refused or fails produces no error and no step change; only a
 * verified sign-in calls `onSignedIn`, and never after `stop`. A request that replaces an older one
 * begins after the older one settled.
 */
export function startPasskeyAutofill(deps: AutofillDeps): Autofill {
  const previous = supersedePasskeyAutofill();
  let stopped = false;
  let stopping: Promise<void> | undefined;
  let settled = false;
  const settledGate = Promise.withResolvers<void>();
  const handle: Autofill = {
    stop() {
      // A request that already settled has no ceremony left, and cancelling would hit an unrelated one.
      if (settled) return Promise.resolve();
      if (stopping) return stopping;
      stopped = true;
      deps.cancel();
      const timer = setInterval(deps.cancel, deps.retryEveryMs ?? 100);
      const bound = Promise.withResolvers<void>();
      const boundTimer = setTimeout(bound.resolve, deps.boundMs ?? 10_000);
      stopping = Promise.race([settledGate.promise, bound.promise]).then(() => {
        clearInterval(timer);
        clearTimeout(boundTimer);
      });
      return stopping;
    },
  };
  latest = handle;
  void (async () => {
    try {
      await previous;
      if (stopped || !(await deps.supported()) || stopped) return;
      const result = await deps.signIn();
      if (stopped || result?.error) return;
      deps.onSignedIn();
    } catch {
      // A rejected or aborted request is never shown.
    } finally {
      settled = true;
      settledGate.resolve();
      if (latest === handle) latest = null;
    }
  })();
  return handle;
}

export const browserPasskeyAutofill = {
  supported: browserSupportsWebAuthnAutofill,
  cancel: () => WebAuthnAbortService.cancelCeremony(),
};
