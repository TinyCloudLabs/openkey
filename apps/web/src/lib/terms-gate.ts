import { writable } from 'svelte/store';
import { checkTerms, type TermsStatus } from './terms';

/**
 * Where this page's signed-in account stands with the Terms. One per page: the root layout drives it for a window or
 * pop-up (cookie session), an embedded frame's page drives it for the frame's session token.
 *
 *   idle      - no one is signed in, or no check has started
 *   checking  - the status is being read; a page goes on loading, the frame's card shows a spinner
 *   open      - nothing is owed: the page is shown
 *   required  - the Terms are shown in place of the page until the account agrees
 *   failed    - the status could not be read: Try again, never the page
 *
 * A check is started by a new sign-in (a new subject) and by `recheck()`, which a refused call (`terms_required`: a
 * release went live while the page was open) runs. An account found to have agreed is remembered for its subject,
 * so moving between pages reads nothing again.
 */
export type TermsGatePhase = 'idle' | 'checking' | 'open' | 'required' | 'failed';
export interface TermsGateState {
  phase: TermsGatePhase;
  /** The release to agree to, while `required`. */
  status: TermsStatus | null;
}

export function createTermsGate(check: typeof checkTerms = checkTerms) {
  const state = writable<TermsGateState>({ phase: 'idle', status: null });
  let phase: TermsGatePhase = 'idle';
  let subject: string | null = null;
  let run = 0;
  let onSignedOut: (() => void) | null = null;

  const set = (next: TermsGateState) => {
    phase = next.phase;
    state.set(next);
  };

  async function read(): Promise<void> {
    const current = ++run;
    set({ phase: 'checking', status: null });
    const result = await check();
    if (current !== run) return;
    switch (result.state) {
      case 'accepted':
        set({ phase: 'open', status: null });
        return;
      case 'required':
        set({ phase: 'required', status: result.status });
        return;
      case 'failed':
        set({ phase: 'failed', status: null });
        return;
      case 'signed-out':
        subject = null;
        set({ phase: 'idle', status: null });
        onSignedOut?.();
    }
  }

  return {
    subscribe: state.subscribe,
    /**
     * The signed-in subject (an account id, or the frame's session token): check it, unless it is the subject already
     * being checked or found to have agreed. `null` resets the gate (signed out). `signedOut` runs when the check finds
     * the credential no longer signs anyone in.
     */
    follow(next: string | null, signedOut?: () => void): void {
      onSignedOut = signedOut ?? null;
      if (next === subject && phase !== 'idle') return;
      subject = next;
      if (next === null) {
        run++;
        set({ phase: 'idle', status: null });
        return;
      }
      void read();
    },
    /** Reads the status again for the current subject. */
    recheck(): void {
      if (subject !== null) void read();
    },
    /** The account agreed: the page is shown. */
    agreed(): void {
      run++;
      set({ phase: 'open', status: null });
    },
  };
}

export const termsGate = createTermsGate();

/**
 * The account was refused for owing the Terms (a release went live while the page was open): the page's Terms gate
 * checks again and shows the Terms in place. Nothing navigates.
 */
export function termsRefused(): void {
  termsGate.recheck();
}
