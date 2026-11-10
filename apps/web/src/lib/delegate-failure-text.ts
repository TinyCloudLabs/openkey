import { apiBusyOrEndedMessage } from './api-busy-or-ended';

const SAFE_CODE = /^[A-Za-z0-9_-]{1,64}$/;
const SHORT_CODE_UNAVAILABLE = 'Short code unavailable. Use the full delegation code instead.';

function safeCode(code: unknown): string | null {
  return typeof code === 'string' && SAFE_CODE.test(code) ? code : null;
}

export function delegateFailureText(cause: unknown): string {
  if (typeof cause === 'object' && cause !== null && 'status' in cause) {
    const { status, code } = cause as { status: number; code: unknown };
    const mappedMessage = apiBusyOrEndedMessage(status);
    if (mappedMessage) return mappedMessage;

    const codeText = safeCode(code);
    return codeText
      ? `Delegation failed (${status} · ${codeText}). Try again.`
      : `Delegation failed (${status}). Try again.`;
  }
  if (cause instanceof Error) return cause.message;
  return 'Delegation failed';

}
export function shortCodeFailureText(status?: number, code?: unknown): string {
  if (status === undefined) return SHORT_CODE_UNAVAILABLE;
  const codeText = safeCode(code);
  return codeText
    ? `Short code unavailable (${status} · ${codeText}). Use the full delegation code instead.`
    : `Short code unavailable (${status}). Use the full delegation code instead.`;
}
