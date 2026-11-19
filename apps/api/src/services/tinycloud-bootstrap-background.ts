/**
 * Bootstrap work an approval leaves running after it answers: a run that outlived its wait, and the
 * retries scheduled after a failed run. Its own module, free of side effects, so the API test preload
 * can end it after every test without loading the logger (TC-2969).
 */
const running = new Set<() => void>();

/** Register one background run; `cancel` stops its later logging, observing and retries. Returns its unregister. */
export function trackTinyCloudBootstrapBackground(cancel: () => void): () => void {
  running.add(cancel);
  return () => {
    running.delete(cancel);
  };
}

/**
 * Test seam: end every background run still going, so none can log, call the test observer or start a
 * retry in a later test. An attempt already running is not interrupted; only what follows it is dropped.
 */
export function cancelTinyCloudBootstrapBackgroundForTests(): void {
  const cancels = [...running];
  running.clear();
  for (const cancel of cancels) cancel();
}
