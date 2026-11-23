/** What the embedded sheet says when the passkey prompt ends with no passkey used: none matched, the browser refused it here, or the person dismissed it. */
export const PASSKEY_NOT_USABLE_TEXT = "That passkey couldn't be used here. Try another passkey or choose Continue with email.";

/**
 * True for the browser's `NotAllowedError`, thrown as a DOMException or wrapped by `@simplewebauthn/browser` in a
 * `WebAuthnError` (code `ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY`) that keeps the DOMException as `cause`.
 */
export function isPasskeyNotAllowed(error: unknown): boolean {
  const named = (value: unknown) => typeof value === 'object' && value !== null && (value as { name?: unknown }).name === 'NotAllowedError';
  return named(error) || named((error as { cause?: unknown } | null | undefined)?.cause);
}

/** What the sheet shows for an error thrown by the passkey sign-in: plain words for a `NotAllowedError`, else the error's own message. */
export function embedPasskeySignInErrorText(error: unknown): string {
  if (isPasskeyNotAllowed(error)) return PASSKEY_NOT_USABLE_TEXT;
  return (error as { message?: string } | null | undefined)?.message || 'Passkey sign-in failed';
}
