// The embed's session token, held by the account setup window for its five setup calls (`api.accountSetup`) and the key
// list it reads.
//
// The token comes in the request message of the OpenKey window that opened this one (`readAccountSetupBearer`). It
// lives in this variable only: never in storage, a cookie, the URL or a log line, and it is gone when the window
// unloads. The API accepts it on the setup routes alone and only with the OpenKey Origin; the owner's passkey (or the
// emailed code) confirms every approval.

let held: string | null = null;
const droppedListeners = new Set<() => void>();

export const heldSetupBearer = (): string | null => held;

export function holdSetupBearer(token: string | null): void {
  held = token;
}

/** The API refused the token: forget it and tell the page, which shows the sign-in screen. */
export function dropSetupBearer(): void {
  if (held === null) return;
  held = null;
  for (const listener of [...droppedListeners]) listener();
}

export function onSetupBearerDropped(listener: () => void): () => void {
  droppedListeners.add(listener);
  return () => droppedListeners.delete(listener);
}
