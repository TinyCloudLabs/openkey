// Share invitation approval requests (TC-2234).
//
// A requester (Courier, the CLI) asks the owner to approve one share invitation. The signed request carries a
// `context` describing the invitation and no permissions of its own. OpenKey generates the share key id when the
// owner prepares the approval, so a request can never name a key that already exists, and the delegation it
// signs holds only `key.create` and `decrypt` on that one key.
import { parseApprovalRequest, type OpenKeyApprovalRequestV1 } from '@tinycloud/share-envelope/links';
import { POLICY_ROOT_MAX_LIFETIME_SECONDS } from '@tinycloud/share-envelope';
import { ENCRYPTION } from '@tinycloud/bootstrap';
import { getAddress } from 'viem';
import { ApprovalResultError } from './approval-results';
import { isRawRecapEntry, parsePreparedRecap, type RecapEntry } from '../routes/delegate-session';

/** The one permission OpenKey issues for a share invitation. */
export interface ShareInvitationGrant {
  service: string;
  path: string;
  actions: string[];
}

export interface ShareInvitationContext {
  kind: 'share-invitation';
  version: 1;
  invitationId: string;
  recipientEmail: string;
  subjectKind: 'session' | 'file';
  subjectName: string;
  /** The deadline to accept the invitation. The key delegation ends before it. */
  acceptanceExpiresAt: string;
  /**
   * When the recipient's access to the shared item ends. A session invitation's equals the acceptance deadline; a
   * file invitation's may be later. Not the key delegation's expiry.
   */
  accessExpiresAt: string;
}

/** An approval request, with the share invitation context when it names one. */
export type ApprovalRequestV1 = OpenKeyApprovalRequestV1 & { context?: ShareInvitationContext };

export const SHARE_KEY_CREATE = 'tinycloud.encryption/key.create';
/** The two abilities the invitation key grants, in the order OpenKey signs them. */
export const SHARE_INVITATION_KEY_ACTIONS: readonly string[] = [SHARE_KEY_CREATE, ENCRYPTION.DECRYPT];
/** The longest delegation an invitation key approval signs. */
export const SHARE_INVITATION_MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;

const CONTEXT_FIELDS = ['kind', 'version', 'invitationId', 'recipientEmail', 'subjectKind', 'subjectName', 'acceptanceExpiresAt', 'accessExpiresAt'];
// A ULID: 26 Crockford base32 characters whose first character keeps it within 128 bits.
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
// Control, format (bidirectional overrides, zero-width) and line or paragraph separator characters.
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const EMAIL = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const SHARE_KEY_URN = /^urn:tinycloud:encryption:did:pkh:eip155:([1-9][0-9]*):(0x[0-9a-fA-F]{40}):default\/share\/([0-9a-f]{32})$/;

function invalid(message: string): ApprovalResultError {
  return new ApprovalResultError('invalid_request', message, 400);
}

/** A UTC time in whole seconds, exactly as `toISOString()` writes it, from 1970 on. */
function canonicalInstant(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/.test(value) ||
    Number.isNaN(Date.parse(value)) || Date.parse(value) < 0 || new Date(value).toISOString() !== value) {
    throw invalid(`Share invitation ${name} must be a UTC time in whole seconds`);
  }
  return value;
}

/** Strict: exactly the context fields, each in its canonical form. */
export function parseShareInvitationContext(value: unknown): ShareInvitationContext {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid('Share invitation context must be an object');
  const context: Record<string, unknown> = { ...value };
  const keys = Object.keys(context);
  if (keys.length !== CONTEXT_FIELDS.length || !CONTEXT_FIELDS.every((field) => Object.hasOwn(context, field))) {
    throw invalid('Share invitation context has missing or unknown fields');
  }
  if (context.kind !== 'share-invitation' || context.version !== 1) throw invalid('Unsupported share invitation context');
  if (typeof context.invitationId !== 'string' || !ULID.test(context.invitationId)) throw invalid('Share invitation id must be a ULID');
  const email = context.recipientEmail;
  if (typeof email !== 'string' || email.length > 254 || !EMAIL.test(email)) {
    throw invalid('Share invitation recipient must be a canonical lowercase email address');
  }
  if (context.subjectKind !== 'session' && context.subjectKind !== 'file') throw invalid('Share invitation subject must be a session or a file');
  const name = context.subjectName;
  if (typeof name !== 'string' || name.length === 0 || [...name].length > 120 || name.trim() !== name || UNSAFE_TEXT.test(name)) {
    throw invalid('Share invitation subject name must be 1 to 120 printable characters');
  }
  const acceptanceExpiresAt = canonicalInstant(context.acceptanceExpiresAt, 'acceptanceExpiresAt');
  const accessExpiresAt = canonicalInstant(context.accessExpiresAt, 'accessExpiresAt');
  if (context.subjectKind === 'session' ? accessExpiresAt !== acceptanceExpiresAt : Date.parse(accessExpiresAt) < Date.parse(acceptanceExpiresAt)) {
    throw invalid(context.subjectKind === 'session'
      ? 'Share invitation accessExpiresAt must equal acceptanceExpiresAt for a session'
      : 'Share invitation accessExpiresAt must not be before acceptanceExpiresAt for a file');
  }
  return {
    kind: 'share-invitation',
    version: 1,
    invitationId: context.invitationId,
    recipientEmail: email,
    subjectKind: context.subjectKind,
    subjectName: name,
    acceptanceExpiresAt,
    accessExpiresAt,
  };
}

// The published request parser predates `context` and needs at least one permission. A share invitation request
// carries none, so its other fields are checked with this stand-in entry, which is never stored or signed.
const STAND_IN_PERMISSION = { service: 'tinycloud.encryption', space: 'encryption', path: '', actions: [ENCRYPTION.DECRYPT] };

/**
 * Parses a signed approval request. A request with a share invitation `context` must carry no permissions, a
 * grant lifetime of at most 24 hours, and an acceptance deadline no later than its link expiry and no more than
 * 24 hours after the link was issued.
 */
export function parseApprovalRequestV1(value: unknown, options: { issuer: string; linkIssuedAt: Date; linkExpiresAt: Date }): ApprovalRequestV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !('context' in value)) {
    return parseApprovalRequest(value, { issuer: options.issuer });
  }
  const { context: rawContext, ...rest } = value;
  const context = parseShareInvitationContext(rawContext);
  if (!('permissions' in rest) || !Array.isArray(rest.permissions) || rest.permissions.length !== 0) {
    throw invalid('A share invitation request names no permissions; OpenKey issues its key');
  }
  const parsed = parseApprovalRequest({ ...rest, permissions: [STAND_IN_PERMISSION] }, { issuer: options.issuer });
  if (parsed.grantLifetimeSeconds * 1000 > SHARE_INVITATION_MAX_LIFETIME_MS) {
    throw invalid('A share invitation request lasts at most 24 hours');
  }
  const acceptBy = Date.parse(context.acceptanceExpiresAt);
  if (acceptBy <= options.linkIssuedAt.getTime()) {
    throw invalid('A share invitation must be accepted after its approval link was issued');
  }
  if (acceptBy > options.linkExpiresAt.getTime() || acceptBy > options.linkIssuedAt.getTime() + SHARE_INVITATION_MAX_LIFETIME_MS) {
    throw invalid('A share invitation must be accepted before its approval link expires, within 24 hours');
  }
  // The recipient's access is authorized by policy roots signed when the share is published, after this approval,
  // and a policy root lasts at most POLICY_ROOT_MAX_LIFETIME_SECONDS. Measured from the link's signed issue time, an
  // access within that span always fits; a longer one is refused here, before the owner approves, never shortened.
  if (Date.parse(context.accessExpiresAt) - options.linkIssuedAt.getTime() > POLICY_ROOT_MAX_LIFETIME_SECONDS * 1000) {
    const days = POLICY_ROOT_MAX_LIFETIME_SECONDS / 86_400;
    throw new ApprovalResultError('invitation_access_too_long',
      `This invitation asks for file access longer than ${days} days, which OpenKey can't approve. Ask the app to send a new invitation for ${days} days or less.`, 400);
  }
  return { ...parsed, permissions: [], context };
}

/** The share invitation a stored request names, if any. */
export function shareInvitationOf(request: object): ShareInvitationContext | undefined {
  return 'context' in request && request.context !== undefined ? parseShareInvitationContext(request.context) : undefined;
}

/** The owner's one share key: `urn:tinycloud:encryption:<owner>:default/share/<id>`, owner in EIP-55 form. */
export function shareInvitationKeyUrn(signer: { address: string; chainId: number }, shareKeyId: string): string {
  if (!/^[0-9a-f]{32}$/.test(shareKeyId)) throw new Error('Share key id must be 32 lowercase hex characters');
  return `urn:tinycloud:encryption:did:pkh:eip155:${signer.chainId}:${getAddress(signer.address)}:default/share/${shareKeyId}`;
}

/** The share key id in `urn` when it is exactly the signer's own share key URN, else null. */
export function signerShareKeyId(urn: string, signer: { address: string; chainId: number }): string | null {
  const match = SHARE_KEY_URN.exec(urn);
  if (!match || match[1] !== String(signer.chainId) || match[2] !== getAddress(signer.address)) return null;
  return match[3]!;
}

/**
 * True when `permissions` is the one entry OpenKey issues for a share invitation: `key.create` and `decrypt` on a
 * `default/share/<32 hex>` key, owned by `signer` when given.
 */
export function isShareInvitationGrant(permissions: unknown, signer?: { address: string; chainId: number }): permissions is [ShareInvitationGrant] {
  if (!Array.isArray(permissions) || permissions.length !== 1) return false;
  const entry: unknown = permissions[0];
  if (!entry || typeof entry !== 'object' || Object.keys(entry).sort().join() !== 'actions,path,service') return false;
  if (!('service' in entry && 'path' in entry && 'actions' in entry) || entry.service !== 'tinycloud.encryption' ||
    typeof entry.path !== 'string' || !Array.isArray(entry.actions) ||
    entry.actions.length !== SHARE_INVITATION_KEY_ACTIONS.length ||
    entry.actions.some((action, index) => action !== SHARE_INVITATION_KEY_ACTIONS[index])) {
    return false;
  }
  return SHARE_KEY_URN.test(entry.path) && (signer === undefined || signerShareKeyId(entry.path, signer) !== null);
}

/**
 * True when the signed SIWE's ReCap names only the issued key and grants only its abilities (the owner may have
 * narrowed them): no other resource, space or ability.
 */
export function signedRecapHoldsOnly(siwe: string, grant: ShareInvitationGrant): boolean {
  let entries: RecapEntry[];
  try { entries = parsePreparedRecap(siwe); } catch { return false; }
  if (entries.length !== 1 || !isRawRecapEntry(entries[0]!) || entries[0]!.path !== grant.path) return false;
  const actions = entries[0]!.actions;
  return actions.length > 0 && new Set(actions).size === actions.length && actions.every((action) => grant.actions.includes(action));
}

/**
 * The SIWE `Request ID` a share invitation approval carries: the approval request id and the CID of its sealed
 * body, as OpenKey stored them. The requester compares it with its own pending request before using the key.
 */
export function approvalRequestBinding(record: { id: string; bodyCid: string }): string {
  return `urn:tinycloud:approval-request:${record.id}:${record.bodyCid}`;
}
