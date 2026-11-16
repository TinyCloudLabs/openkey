// Renewing permissions in Settings (TC-2946): the account's renewal leases and stopping one.
import { buildSummaryStatements, parseCapabilityReview } from '@openkey/capability-review';

export interface RenewalLease {
  leaseCid: string;
  originalCid: string;
  nodeOrigin: string;
  approvedAt: string;
  leaseExpiresAt: string;
  /** The grant's own signed end: where it ends once renewal stops. */
  grantExpiresAt: string | null;
  /** `wallet`: an external wallet signed the lease, so it signs the stop too. */
  signer: 'openkey' | 'wallet';
  reason: string | null;
  /** The approved grant's SIWE message, as signed: its permissions are shown as the approval screen showed them. */
  grantSiwe: string;
}

export const renewalLeaseCopy = {
  title: 'Renewing permissions',
  intro: "These permissions renew automatically. Stopping renewal can't be undone: the permission then ends on the date it had when you approved it, or right away if that date has passed. To renew it again, the app has to ask you.",
  untitled: (host: string) => `Permission on ${host}`,
  empty: 'No permissions are renewing.',
  renewsUntil: 'Renews until',
  approved: 'Approved',
  stop: 'Stop renewal',
  stopping: 'Stopping…',
  stopped: (grantExpiresAt: string | null, now = Date.now()) => {
    const end = grantExpiresAt ? new Date(grantExpiresAt) : null;
    if (!end || Number.isNaN(end.getTime())) return 'Renewal stopped.';
    return end.getTime() <= now
      ? 'Renewal stopped. This permission ends now.'
      : `Renewal stopped. This permission ends on ${end.toLocaleDateString(undefined, { dateStyle: 'medium' })}.`;
  },
  walletPrompt: 'Sign with your wallet to stop renewal.',
  walletUnavailable: "Your wallet isn't available here. Open this page where your wallet is installed.",
  walletDeclined: "You didn't sign, so renewal is still on.",
  failed: "Couldn't stop renewal, so it's still on. Try again.",
  loadFailed: "Couldn't load your renewing permissions. Reload to try again.",
} as const;

/**
 * The approval screen's own summary rows for the signed grant, so the owner sees here what they approved there.
 * Empty when the message carries no readable permissions.
 */
export function leaseStatements(grantSiwe: string): string[] {
  const address = /^(0x[0-9a-fA-F]{40})$/m.exec(grantSiwe)?.[1];
  const chainId = Number(/^Chain ID: ([1-9][0-9]*)$/m.exec(grantSiwe)?.[1]);
  if (!address || !Number.isSafeInteger(chainId)) return [];
  const review = parseCapabilityReview({
    message: grantSiwe,
    signer: { label: 'Owner', address, chainId, provenance: 'managed' },
    editable: false,
    metadataTrust: { status: 'unsigned', reason: 'Settings shows an approved grant' },
    reason: { text: '', source: 'none' },
    requester: { displayName: '', verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false },
  });
  return review.protocol === 'tinycloud-siwe-recap' ? buildSummaryStatements(review.permissions).map((statement) => statement.primaryText) : [];
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
