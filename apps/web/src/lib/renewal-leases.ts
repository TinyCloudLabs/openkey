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
  /** A sign-in lease recorded under the session being signed out: signing out stops it. */
  endsOnSignOut: boolean;
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
  /** By a sign-out button on the dashboard, shown only while apps other than this sign-in keep renewing. */
  signOutKeepsRenewing: 'Apps you allowed to stay signed in keep renewing after you sign out.',
  /** The dashboard's link to Renewing permissions in Settings. */
  stopRenewalsLink: 'Stop renewals',
  /** Inside apps, where OpenKey settings is a step away: what signing out ends, then what it leaves on. */
  signOutEndsThisApp: 'Signing out ends this app’s sign-in and its renewal.',
  signOutKeepsOthersRenewing: 'Other apps you allowed to stay signed in keep renewing.',
  stopRenewalsInSettings: 'To stop them, choose Stop renewal under Renewing permissions in OpenKey settings.',
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
