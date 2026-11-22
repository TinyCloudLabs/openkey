// Every on-screen word of the passkey fallback on the sign-in page lives here, so the wording changes
// without touching the sign-in logic.
export const PASSKEY_FALLBACK_COPY = {
  // Shown in the native passkey step when the passkey prompt ends with no passkey used.
  message: 'No passkey was used. Sign in with an email code, and OpenKey offers to add a passkey to this device.',
  // Moves from that step to the email step.
  emailButton: 'Use an email code',
} as const;
