// Renewing permissions in Settings (TC-2946): the account's renewal leases and stopping one.
export interface RenewalLease {
  leaseCid: string;
  originalCid: string;
  nodeOrigin: string;
  approvedAt: string;
  leaseExpiresAt: string;
  /** `wallet`: an external wallet signed the lease, so it signs the stop too. */
  signer: 'openkey' | 'wallet';
  reason: string | null;
  permissions: Array<{ service: string; path: string; actions: string[] }>;
}

export const renewalLeaseCopy = {
  title: 'Renewing permissions',
  intro: "These permissions renew automatically. If you stop renewal, a permission ends on the date it had when you approved it, or now if that date has passed. You can't turn renewal back on; the app has to ask again.",
  untitled: (host: string) => `Permission on ${host}`,
  empty: 'No permissions are renewing.',
  renewsUntil: 'Renews until',
  approved: 'Approved',
  stop: 'Stop renewal',
  stopping: 'Stopping…',
  stopped: 'Renewal stopped.',
  walletPrompt: 'Sign with your wallet to stop renewal.',
  walletUnavailable: "Your wallet isn't available here. Open this page where your wallet is installed.",
  walletDeclined: 'Renewal is still on. You declined the signature.',
  failed: "The node didn't confirm. Renewal is still on. Try again.",
  loadFailed: "Couldn't load your renewing permissions. Reload to try again.",
} as const;

/** One plain line per signed permission: where it applies and what it allows. */
export function describeLeasePermissions(permissions: RenewalLease['permissions']): string[] {
  return permissions.map(({ service, path, actions }) => {
    const verbs = actions.map((action) => action.slice(action.lastIndexOf('/') + 1)).join(', ');
    return `${service.replace(/^tinycloud\./, '')}${path ? ` ${path}` : ''}: ${verbs}`;
  });
}

export function nodeHost(origin: string): string {
  try { return new URL(origin).host; } catch { return origin; }
}

/** After a sign-out whose renewing permissions were not all stopped. */
export function signOutRenewalNotice(notStopped: number): string {
  return notStopped === 1
    ? "You're signed out, but 1 permission is still renewing. Sign in again and stop it under Renewing permissions in Settings."
    : `You're signed out, but ${notStopped} permissions are still renewing. Sign in again and stop them under Renewing permissions in Settings.`;
}
