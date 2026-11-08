// Both authorization contexts and preview approvals have a five-minute API lifetime.
const MAX_LIFETIME_MS = 5 * 60_000;
export const PREVIEW_EXPIRED_MESSAGE = 'This request expired. Ask the app to send it again.';

export interface SigningPreview {
  input: string;
  revision: number;
  authorizationContextToken: string;
  previewApprovalToken: string;
  signedMessage: string;
  selectedActionIds: string[];
  deadline: number;
}

/** Conservative monotonic deadline, including request time and HTTP Date rounding. */
export function signingPreviewDeadline(
  expiresAt: unknown,
  serverDate: string | null,
  requestStarted: number,
  receivedAt = performance.now(),
  receivedWallTime = Date.now(),
): number {
  const expiry = typeof expiresAt === 'string' ? Date.parse(expiresAt) : NaN;
  const serverNow = serverDate === null ? receivedWallTime : Date.parse(serverDate);
  if (!Number.isFinite(expiry) || !Number.isFinite(serverNow)) {
    throw new Error("OpenKey couldn't check this request. Ask the app to try again.");
  }
  // Starting at request dispatch also bounds a missing Date header despite a slow device clock.
  const lifetime = Math.min(MAX_LIFETIME_MS, expiry - serverNow - (serverDate === null ? 0 : 1000));
  const deadline = requestStarted + lifetime;
  if (deadline <= receivedAt) throw new Error(PREVIEW_EXPIRED_MESSAGE);
  return deadline;
}
