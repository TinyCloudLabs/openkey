// OpenKey device authorization (TC-539): the CLI requests an explicit,
// bounded permission set; the owner may narrow it on /delegate. The relay
// binding and the relayed delegation must both state exactly the approved
// subset, in the request's own manifest form, so the CLI can compare them.

export interface DevicePermission {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

/** Copy for the retired one-shot Share upload request, which carries no reason. */
export const SHARE_ONLY_DEVICE_REASON =
  'Publish encrypted files through TinyCloud Share using one-shot Node upload attestations.';

/** `GET /api/device-authorizations/lookup` response (dates as ISO strings). */
export interface DeviceRequestRecord {
  id: string;
  userCode: string;
  sessionDid: string;
  publicJwk: Record<string, unknown>;
  relayPublicJwk: Record<string, unknown>;
  permissions: DevicePermission[];
  nodeOrigin: string;
  shareOrigin: string;
  delegationExpiresAt: string;
  transactionExpiresAt: string;
  // Absent from APIs older than TC-539: Pages can deploy before the API.
  reason?: string;
  shareOnly?: boolean;
  delegationTtlSeconds?: number;
}

/** Values a `/delegate` device link carries that must equal the server's request. */
export interface DeviceDelegateLink {
  transactionId: string;
  sessionDid: string;
  publicJwk: unknown;
  relayPublicJwk: unknown;
  nodeOrigin: string;
  shareOrigin: string;
  permissions: unknown;
  /** The `/delegate` `expiry` parameter, `<seconds>s`. */
  expiry: string;
}

/**
 * Consent text as shown to the owner: invisible format and bidirectional
 * override characters removed, control characters as spaces, whitespace
 * collapsed. Mirrors the API's reason cleaning.
 */
export function cleanConsentText(value: string): string {
  return value
    .replace(/[\u00ad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u3164\ufeff\uffa0\u{e0000}-\u{e007f}]/gu, '')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export async function lookupDeviceRequest(apiBase: string, userCode: string): Promise<DeviceRequestRecord | null> {
  const response = await fetch(`${apiBase}/api/device-authorizations/lookup?user_code=${encodeURIComponent(userCode)}`, {
    credentials: 'omit',
    headers: { accept: 'application/json' },
  });
  return response.ok ? ((await response.json()) as DeviceRequestRecord) : null;
}

/**
 * Look up the pending device request behind a `/delegate` link and refuse
 * the link unless every binding it carries equals the server's request and
 * its `expiry` (`<seconds>s`) is within the requested lifetime, so a crafted
 * link cannot swap keys, origins, scope, reason, or lifetime.
 */
export async function loadVerifiedDeviceRequest(
  apiBase: string,
  userCode: string,
  link: DeviceDelegateLink,
): Promise<DeviceRequestRecord> {
  const record = userCode ? await lookupDeviceRequest(apiBase, userCode) : null;
  if (!record) throw new Error('This device request is invalid or expired. Restart the CLI command and enter its code at /device.');
  const canonical = (value: unknown) => JSON.stringify(value, (_key, entry: unknown) =>
    entry && typeof entry === 'object' && !Array.isArray(entry)
      ? Object.fromEntries(Object.entries(entry).sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)))
      : entry);
  if (
    record.id !== link.transactionId ||
    record.sessionDid !== link.sessionDid ||
    record.nodeOrigin !== link.nodeOrigin ||
    record.shareOrigin !== link.shareOrigin ||
    canonical(record.publicJwk) !== canonical(link.publicJwk) ||
    canonical(record.relayPublicJwk) !== canonical(link.relayPublicJwk) ||
    canonical(record.permissions) !== canonical(link.permissions) ||
    !(Number(/^(\d+)s$/.exec(link.expiry)?.[1]) <= deviceRequestTtlSeconds(record))
  ) {
    throw new Error('This approval link does not match the device request. Enter the code from your terminal at /device.');
  }
  return record;
}

export function isShareOnlyDeviceRequest(record: DeviceRequestRecord): boolean {
  const [only] = record.permissions;
  return record.shareOnly ?? (record.permissions.length === 1 && only?.service === 'tinycloud.capabilities' && only.space === 'applications');
}

/** The server-cleaned reason, or fixed copy for the legacy Share-only request. */
export function deviceRequestReason(record: DeviceRequestRecord): string {
  return record.reason ?? (isShareOnlyDeviceRequest(record) ? SHARE_ONLY_DEVICE_REASON : '');
}

/**
 * The lifetime the CLI requested. APIs older than TC-539 report only the
 * padded deadline (transaction deadline + TTL, up to 90 days), so derive the
 * TTL from the two deadlines and clamp it to 60 seconds..30 days. Time
 * remaining until the padded deadline would overshoot it once signing
 * starts after lookup.
 */
export function deviceRequestTtlSeconds(record: DeviceRequestRecord): number {
  if (typeof record.delegationTtlSeconds === 'number' && Number.isFinite(record.delegationTtlSeconds)) {
    return record.delegationTtlSeconds;
  }
  const derived = Math.floor((Date.parse(record.delegationExpiresAt) - Date.parse(record.transactionExpiresAt)) / 1000);
  return Math.min(2_592_000, Math.max(60, Number.isFinite(derived) ? derived : 60));
}

/** Lifetime choices up to (and ending with) the requested maximum. */
export function deviceLifetimeOptions(maxSeconds: number): Array<{ seconds: number; label: string }> {
  return [
    ...[86_400, 604_800, 2_592_000]
      .filter((seconds) => seconds < maxSeconds)
      .map((seconds) => ({ seconds, label: formatDeviceLifetime(seconds) })),
    { seconds: maxSeconds, label: `${formatDeviceLifetime(maxSeconds)} (requested maximum)` },
  ];
}

const PKH_SPACE = /^tinycloud:pkh:eip155:([1-9][0-9]{0,19}):(0x[0-9a-fA-F]{40}):([A-Za-z0-9][A-Za-z0-9._-]{0,63})$/;

/**
 * Whether a signed grant's space (always a full `tinycloud:pkh` URI with an
 * EIP-55 address) is the requested space. Ethereum addresses compare
 * case-insensitively; the chain and space name stay exact. A bare requested
 * name matches the signer's space of that name.
 */
function isRequestedSpace(requested: string, granted: string): boolean {
  const grant = PKH_SPACE.exec(granted);
  if (!grant) return granted === requested;
  const request = PKH_SPACE.exec(requested);
  if (!request) return grant[3] === requested;
  return request[1] === grant[1] && request[2]!.toLowerCase() === grant[2]!.toLowerCase() && request[3] === grant[3];
}

/** Base64url of the UTF-8 JSON encoding, as the CLI and `/device` send it. */
export function encodeBase64UrlJson(value: unknown): string {
  let binary = '';
  for (const byte of new TextEncoder().encode(JSON.stringify(value))) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Inverse of `encodeBase64UrlJson`: the bytes are UTF-8, not Latin-1. */
export function decodeBase64UrlJson(value: string): unknown {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(binary, (char) => char.charCodeAt(0))));
}

/**
 * Map the grants of a signed delegation (`/api/delegate` `permissions`,
 * ReCap form: short service names and full space URIs) back onto the
 * requested manifest permissions, keeping the request's spelling. Throws
 * when the delegation carries anything the device request did not ask for
 * or grants nothing.
 */
export function approvedDevicePermissions(requested: DevicePermission[], granted: unknown): DevicePermission[] {
  if (!Array.isArray(granted)) throw new Error('The approved delegation does not list its permissions.');
  const grantedActions = new Map<DevicePermission, Set<string>>();
  for (const raw of granted) {
    const grant = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
    const service = typeof grant.service === 'string' && !grant.service.startsWith('tinycloud.')
      ? `tinycloud.${grant.service}`
      : grant.service;
    const source = requested.find((permission) =>
      permission.service === service &&
      permission.path === grant.path &&
      typeof grant.space === 'string' &&
      isRequestedSpace(permission.space, grant.space),
    );
    const actions = Array.isArray(grant.actions) ? grant.actions : [];
    if (!source || actions.some((action) => typeof action !== 'string' || !source.actions.includes(action))) {
      throw new Error('The approved delegation exceeds the device request.');
    }
    const known = grantedActions.get(source) ?? new Set<string>();
    for (const action of actions) known.add(action as string);
    grantedActions.set(source, known);
  }
  const approved = requested.flatMap((permission) => {
    const actions = permission.actions.filter((action) => grantedActions.get(permission)?.has(action));
    return actions.length > 0 ? [{ ...permission, actions }] : [];
  });
  if (approved.length === 0) throw new Error('The approved delegation grants no requested permission.');
  return approved;
}

/** Human lifetime for a delegation that lasts `seconds`, rounded down. */
export function formatDeviceLifetime(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  if (days >= 1) return days === 1 ? '1 day' : `${days} days`;
  const hours = Math.floor(seconds / 3_600);
  if (hours >= 1) return hours === 1 ? '1 hour' : `${hours} hours`;
  const minutes = Math.max(1, Math.floor(seconds / 60));
  return minutes === 1 ? '1 minute' : `${minutes} minutes`;
}
