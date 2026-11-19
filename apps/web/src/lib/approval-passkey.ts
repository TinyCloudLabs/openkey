// TC-3442: an approval the account's setting says needs a passkey carries an assertion bound to that request. The
// API hands out the challenge (an "offer"); this answers it with the passkey prompt and returns what the approval
// sends back as `passkeyAssertion`.
import {
  startAuthentication,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';

/** Whether Settings shows the "Passkey for approvals" card. */
export const PASSKEY_APPROVAL_SETTING_SHOWN = false;

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
