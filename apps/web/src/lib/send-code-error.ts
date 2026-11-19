/** Error `code` the API answers (502) when the sign-in email could not be sent. */
export const EMAIL_DELIVERY_FAILED_CODE = 'EMAIL_DELIVERY_FAILED';

type SendCodeError = { code?: unknown; message?: unknown } | null | undefined;

/**
 * The message under the email form when the API cannot send the code. Other failures keep the
 * API's own message, or `fallback` when it has none.
 */
export function sendCodeErrorMessage(
  error: SendCodeError,
  options: { email: string; passkey: boolean; fallback: string },
): string {
  if (error?.code !== EMAIL_DELIVERY_FAILED_CODE) {
    return typeof error?.message === 'string' && error.message ? error.message : options.fallback;
  }
  const email = options.email.trim();
  const message = email
    ? `We couldn't send the code to ${email}. Please try again in a few minutes.`
    : "We couldn't send your code. Please try again in a few minutes.";
  return options.passkey ? `${message} You can also sign in with a passkey.` : message;
}
