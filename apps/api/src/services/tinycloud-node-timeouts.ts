import { activateSessionWithHost, type SpaceHostResult } from '@tinycloud/sdk-core';
import { isKnownTinyCloudActivationHost } from './tinycloud-hosts';

// Every request OpenKey makes to the TinyCloud node on an approval is bounded, so a hung call
// fails its run (and releases the setup lock) instead of holding an approval or the lock (TC-1608).
const DEFAULT_NODE_CALL_TIMEOUT_MS = 15_000;
const DEFAULT_NODE_INVOKE_TIMEOUT_MS = 30_000;
const MAX_NODE_TIMEOUT_MS = 60_000;

function nodeTimeoutMs(value: string | undefined, fallback: number): number {
  const configured = value?.trim() ? Number(value) : NaN;
  return Number.isFinite(configured) && configured > 0 ? Math.min(configured, MAX_NODE_TIMEOUT_MS) : fallback;
}

/** Peer id, host delegation and session activation. Read per call from TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS. */
export function tinyCloudBootstrapNodeCallTimeoutMs(env: Record<string, string | undefined> = process.env): number {
  return nodeTimeoutMs(env.TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS, DEFAULT_NODE_CALL_TIMEOUT_MS);
}

/** Schema, seed and encryption-network requests. Read per call from TINYCLOUD_BOOTSTRAP_NODE_INVOKE_TIMEOUT_MS. */
export function tinyCloudBootstrapNodeInvokeTimeoutMs(env: Record<string, string | undefined> = process.env): number {
  return nodeTimeoutMs(env.TINYCLOUD_BOOTSTRAP_NODE_INVOKE_TIMEOUT_MS, DEFAULT_NODE_INVOKE_TIMEOUT_MS);
}

/**
 * The approval routes' own session activation, bounded like the setup's calls. sdk-core's
 * `activateSessionWithHost` takes no AbortSignal, so the wait is cut at the timeout and the request is
 * left to end on its own: it holds no lock and no state. A timeout rejects, which the routes already
 * report as `hostActivated: false` (the web page then activates on its own). Only known TinyCloud
 * hosts are activated; any other host gets `success: false` and `hostNotKnown: true` without a request.
 */
export async function activateSessionWithinTimeout(
  host: string,
  delegationHeader: { Authorization: string },
): Promise<SpaceHostResult & { hostNotKnown?: true }> {
  if (!isKnownTinyCloudActivationHost(host)) {
    return { success: false, status: 0, hostNotKnown: true, error: 'Session activation only runs on known TinyCloud hosts.' };
  }
  const signal = AbortSignal.timeout(tinyCloudBootstrapNodeCallTimeoutMs());
  const { promise: timedOut, reject } = Promise.withResolvers<never>();
  const onTimeout = () => reject(new Error('TinyCloud node session activation timed out.'));
  signal.addEventListener('abort', onTimeout, { once: true });
  const activation = activateSessionWithHost(host, delegationHeader);
  // The request outlives a timeout: its late failure must not become an unhandled rejection.
  activation.catch(() => undefined);
  try {
    return await Promise.race([activation, timedOut]);
  } finally {
    signal.removeEventListener('abort', onTimeout);
  }
}
