// Close button for the CLI paste-code page.
//
// `window.close()` only works for windows the script opened, so the page
// checks after CLOSE_CHECK_MS whether it is still open:
//   1. still open and there is history: `history.back()`, then check again;
//   2. still open with no history (or still open after going back): `onStuck`.
// A closed window or a navigation away from the page cancels the pending checks.

export const CLOSE_CHECK_MS = 300;

export type CloseEnvironment = {
  close(): void;
  isClosed(): boolean;
  historyLength(): number;
  back(): void;
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
};

/** Returns a cancel function that clears any pending check. */
export function closeThisTab(env: CloseEnvironment, onStuck: () => void): () => void {
  let handle: unknown = null;
  let cancelled = false;

  const later = (callback: () => void) => {
    handle = env.setTimeout(callback, CLOSE_CHECK_MS);
  };
  const afterBack = () => {
    if (!cancelled && !env.isClosed()) onStuck();
  };
  const afterClose = () => {
    if (cancelled || env.isClosed()) return;
    if (env.historyLength() > 1) {
      env.back();
      later(afterBack);
    } else {
      onStuck();
    }
  };

  env.close();
  later(afterClose);
  return () => {
    cancelled = true;
    if (handle !== null) env.clearTimeout(handle);
  };
}

export function browserCloseEnvironment(win: Window = window): CloseEnvironment {
  return {
    close: () => win.close(),
    isClosed: () => win.closed,
    historyLength: () => win.history.length,
    back: () => win.history.back(),
    setTimeout: (callback, ms) => win.setTimeout(callback, ms),
    clearTimeout: (handle) => win.clearTimeout(handle as number),
  };
}
