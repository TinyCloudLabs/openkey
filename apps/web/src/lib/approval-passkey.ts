// TC-3442: an approval the account's setting says needs a passkey carries an assertion bound to that request. The
// API hands out the challenge (an "offer"); this answers it with the passkey prompt and returns what the approval
// sends back as `passkeyAssertion`.
import {
  startAuthentication,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';

export type PasskeyApprovalMode = 'ALWAYS' | 'SENSITIVE' | 'NEVER';

export interface PasskeyApprovalSetting {
  /** The stored choice. */
  mode: PasskeyApprovalMode;
  /** The choice in force: NEVER while the account has no passkey that can confirm approvals. */
  effectiveMode: PasskeyApprovalMode;
  stepUpPasskeys: number;
}

export interface ApprovalPasskeyOffer {
  challengeToken: string;
  options: PublicKeyCredentialRequestOptionsJSON;
}

export interface ApprovalPasskeyAssertion {
  challengeToken: string;
  response: AuthenticationResponseJSON;
}

const MODE_RANK: Record<PasskeyApprovalMode, number> = { NEVER: 0, SENSITIVE: 1, ALWAYS: 2 };

/** Moving to `to` asks for the passkey on fewer approvals, so the API wants a passkey assertion for it. */
export function lowersPasskeyApprovalMode(from: PasskeyApprovalMode, to: PasskeyApprovalMode): boolean {
  return MODE_RANK[to] < MODE_RANK[from];
}

/** Shows the passkey prompt for this offer. Call it straight from the tap: some browsers need the user gesture. */
export async function confirmWithPasskey(offer: ApprovalPasskeyOffer): Promise<ApprovalPasskeyAssertion> {
  const response = await startAuthentication({ optionsJSON: offer.options });
  return { challengeToken: offer.challengeToken, response };
}

/** What an approval screen gets from the API before Approve: whether the tap needs the passkey, with its challenge. */
export type ApprovalPasskeyNeed = { required: false } | ({ required: true } & ApprovalPasskeyOffer);

/** The browser's passkey prompt was dismissed or failed. Nothing reached the API, so the same offer can be tried again. */
export class PasskeyPromptError extends Error {
  constructor(cause: unknown) {
    super(passkeyApprovalCopy.cancelled, { cause });
    this.name = 'PasskeyPromptError';
  }
}

/**
 * The `passkeyAssertion` an approval sends: undefined when the setting doesn't ask, else the answer to the offer.
 * Call it straight from the Approve tap, before any other await, so the browser still sees the gesture.
 * A dismissed or failed prompt throws `PasskeyPromptError`, whose message is the text to show.
 */
export async function answerApprovalPasskey(
  need: ApprovalPasskeyNeed | null | undefined,
): Promise<ApprovalPasskeyAssertion | undefined> {
  if (!need?.required) return undefined;
  try {
    return await confirmWithPasskey(need);
  } catch (error) {
    throw new PasskeyPromptError(error);
  }
}

/**
 * Did the API refuse this approval over the passkey? Its message says to tap Approve again; the challenge is spent,
 * so the screen fetches a new offer before the next tap.
 */
export function isPasskeyApprovalRefusal(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && PASSKEY_REFUSAL_CODES[code] === true;
}

// TC-3442 texts. Any wording change goes back to product sign-off.
export const passkeyApprovalCopy = {
  title: 'Passkey for approvals',
  help: 'When OpenKey asks for your passkey as you tap Approve. Revoking access never asks.',
  choices: [
    { mode: 'ALWAYS', label: 'Every approval' },
    { mode: 'SENSITIVE', label: 'Only for sensitive access (recommended)' },
    { mode: 'NEVER', label: 'Never' },
  ] as const satisfies readonly { mode: PasskeyApprovalMode; label: string }[],
  neverWarning: 'Anyone signed in as you can approve without your passkey.',
  needsPasskey: 'Add a passkey to use this.',
  cancelled: "Your passkey didn't confirm this. Try again.",
  loadFailed: "Couldn't load this setting.",
  offerFailed: "Couldn't get your passkey ready. Tap Approve to try again.",
} as const;

/** The API's passkey refusals speak of an Approve button; Settings has none, so it shows its own line for them. */
const PASSKEY_REFUSAL_CODES: Record<string, true> = {
  passkey_approval_required: true,
  passkey_approval_invalid: true,
  passkey_not_step_up_capable: true,
};

/** What Settings shows when a change is refused: the API's words for its other refusals, else `cancelled`. */
export function passkeyApprovalSettingError(error: unknown): string {
  const { code, message } = (error ?? {}) as { code?: unknown; message?: unknown };
  if (typeof code !== 'string' || PASSKEY_REFUSAL_CODES[code] || typeof message !== 'string' || !message) {
    return passkeyApprovalCopy.cancelled;
  }
  return message;
}

/** Where a screen stands with the offer it fetches for its Approve: not started, in flight, or failed. */
export type PasskeyOfferFetch = 'idle' | 'pending' | 'failed';

/** What Approve does with the offer a screen holds: send (with that offer), wait for it, or fetch it again. */
export type ApprovalPasskeyGate =
  | { action: 'send'; need: ApprovalPasskeyNeed | null }
  | { action: 'wait' }
  | { action: 'retry' };

/**
 * Decides what an Approve tap does about the passkey offer. `input` identifies what the offer must be for (null: the
 * screen needs none, so the approval goes without an assertion); `held` is the offer that landed and the input it was
 * fetched for. An offer fetched for other input never counts. Without a matching offer nothing is sent: while the
 * fetch is in flight the tap waits, otherwise the offer is fetched again.
 */
export function approvalPasskeyGate(state: {
  input: string | null;
  held: { input: string; need: ApprovalPasskeyNeed } | null;
  fetch: PasskeyOfferFetch;
}): ApprovalPasskeyGate {
  if (state.input === null) return { action: 'send', need: null };
  if (state.held?.input === state.input) return { action: 'send', need: state.held.need };
  return { action: state.fetch === 'pending' ? 'wait' : 'retry' };
}
