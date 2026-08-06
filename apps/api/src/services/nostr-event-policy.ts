// Per-kind payload policy for Nostr custody signing.
//
// Every kind in the capability model (packages/tee/src/nostr-capabilities.ts)
// has an explicit validator here that pins the template to the exact shape
// the Buzz web client produces - allowed/required tags, cardinality, value
// syntax, content shape - rather than a broad "any event of this kind"
// pass-through. Being in SUPPORTED_NOSTR_KINDS is necessary but not
// sufficient: a template that fails its kind validator is never signed.
//
// Kind 9 (legacy channel message) deliberately keeps the original PR #169
// behavior: generic bounds only, no kind-specific narrowing, so existing
// integrations keep working unchanged.
//
// Shapes are derived from the pinned Buzz client sources (buzz/web
// src/lib): media.ts (24242), invites.ts + reminders-moderation.ts (27235),
// workspace-state.ts (0, 7, 40002, 20001, 41010), relay-members.ts
// (9030-9032), reminders-moderation.ts (1984, 9040-9044, 30300).
import { DESTINATION_BOUND_NOSTR_KINDS, isValidNip44PayloadShape } from '@openkey/tee';
import { isAllowedNip98Url, relayServerAuthority } from './nostr-destinations';

export interface NostrEventTemplate {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

export type KindPolicyResult = { ok: true } | { ok: false; reason: string };

const HEX_64_RE = /^[0-9a-f]{64}$/;
const HEX_32_RE = /^[0-9a-f]{32}$/;
const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// Host authority as Buzz's serverAuthority produces it: lowercase hostname
// or bracketed IPv6, optional non-default port. Never a scheme or path.
const SERVER_AUTHORITY_RE = /^([a-z0-9]([a-z0-9.-]*[a-z0-9])?|\[[0-9a-f:.]+\])(:[0-9]{1,5})?$/;

const PROFILE_KEYS = new Set(['name', 'display_name', 'picture', 'about', 'nip05']);
const REPORT_TYPES = new Set(['illegal', 'nudity', 'malware', 'spam', 'impersonation', 'profanity', 'other']);
const PRESENCE_STATUSES = new Set(['online', 'away', 'offline']);
const MEMBER_ROLES = new Set(['owner', 'admin', 'member']);
const RESOLVE_STATUSES = new Set(['resolved', 'dismissed']);
const RESOLVE_ACTIONS = new Set(['delete', 'kick', 'ban', 'timeout', 'dismiss', 'escalate']);
const IMETA_KEYS = new Set(['url', 'm', 'x', 'size', 'dim', 'blurhash', 'thumb', 'duration', 'image', 'filename']);
const BLOSSOM_MAX_EXPIRATION_SECONDS = 3600; // Buzz uses 300 (upload) / 600 (get)

/** Kind 30300 content is a NIP-44 v2 payload, which base64-outgrows the plain-text ceiling. */
export const NIP44_CONTENT_KINDS_MAX_LENGTH = 8192;
export const DEFAULT_MAX_CONTENT_LENGTH = 4096;

export function maxContentLengthForKind(kind: number): number {
  return kind === 30300 ? NIP44_CONTENT_KINDS_MAX_LENGTH : DEFAULT_MAX_CONTENT_LENGTH;
}

function fail(reason: string): KindPolicyResult {
  return { ok: false, reason };
}

const OK: KindPolicyResult = { ok: true };

function isPubkeyTag(tag: string[], name = 'p'): boolean {
  return tag.length === 2 && tag[0] === name && HEX_64_RE.test(tag[1]!);
}

function isChannelIdValue(value: string | undefined): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 512;
}

// kind 0 - profile metadata. Buzz signs `buildProfileContent` output: a JSON
// object whose keys are a subset of the five profile fields, values trimmed
// non-empty strings; tags are always empty.
function validateProfileMetadata(t: NostrEventTemplate): KindPolicyResult {
  if (t.tags.length !== 0) return fail('profile_tags_must_be_empty');
  let parsed: unknown;
  try {
    parsed = JSON.parse(t.content);
  } catch {
    return fail('profile_content_invalid');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return fail('profile_content_invalid');
  for (const [key, value] of Object.entries(parsed)) {
    if (!PROFILE_KEYS.has(key)) return fail('profile_content_invalid');
    if (typeof value !== 'string' || value.length === 0 || value.length > 1024) return fail('profile_content_invalid');
  }
  return OK;
}

// kind 7 - reaction: exactly [["e", <message id>], ["h", <channel id>]],
// content is the emoji (short, non-empty).
function validateReaction(t: NostrEventTemplate): KindPolicyResult {
  if (t.content.length === 0 || t.content.length > 64) return fail('reaction_content_invalid');
  if (t.tags.length !== 2) return fail('reaction_tags_invalid');
  const [e, h] = t.tags;
  if (!(e!.length === 2 && e![0] === 'e' && HEX_64_RE.test(e![1]!))) return fail('reaction_tags_invalid');
  if (!(h!.length === 2 && h![0] === 'h' && isChannelIdValue(h![1]))) return fail('reaction_tags_invalid');
  return OK;
}

// kind 40002 - channel message v2: ["h", channel] first, then zero or more
// well-formed imeta attachment tags, then at most one ["e", id, "", "reply"].
function validateChannelMessageV2(t: NostrEventTemplate): KindPolicyResult {
  if (t.tags.length < 1) return fail('channel_message_tags_invalid');
  const [h, ...rest] = t.tags;
  if (!(h!.length === 2 && h![0] === 'h' && isChannelIdValue(h![1]))) return fail('channel_message_tags_invalid');

  let replySeen = false;
  for (const tag of rest) {
    if (tag[0] === 'e') {
      if (replySeen) return fail('channel_message_tags_invalid');
      replySeen = true;
      if (!(tag.length === 4 && HEX_64_RE.test(tag[1]!) && tag[2] === '' && tag[3] === 'reply')) {
        return fail('channel_message_tags_invalid');
      }
      continue;
    }
    if (replySeen) return fail('channel_message_tags_invalid'); // reply tag must be last
    if (tag[0] !== 'imeta') return fail('channel_message_tags_invalid');
    if (!isValidImetaTag(tag)) return fail('channel_message_tags_invalid');
  }
  return OK;
}

function isValidImetaTag(tag: string[]): boolean {
  const seen = new Set<string>();
  for (const part of tag.slice(1)) {
    const spaceAt = part.indexOf(' ');
    if (spaceAt <= 0) return false;
    const key = part.slice(0, spaceAt);
    const value = part.slice(spaceAt + 1);
    if (!IMETA_KEYS.has(key) || seen.has(key) || value.length === 0) return false;
    seen.add(key);
    if (key === 'x' && !HEX_64_RE.test(value)) return false;
    if (key === 'size' && !DECIMAL_RE.test(value)) return false;
    if (key === 'url' || key === 'thumb' || key === 'image') {
      let url: URL;
      try {
        url = new URL(value);
      } catch {
        return false;
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
    }
  }
  return seen.has('url') && seen.has('m') && seen.has('x') && seen.has('size');
}

// kind 1984 - report: exactly [["p", author], ["e", id, type]] with a known
// report type; content is the optional reporter note.
function validateReport(t: NostrEventTemplate): KindPolicyResult {
  if (t.content.length > 2048) return fail('report_content_invalid');
  if (t.tags.length !== 2) return fail('report_tags_invalid');
  const [p, e] = t.tags;
  if (!isPubkeyTag(p!)) return fail('report_tags_invalid');
  if (!(e!.length === 3 && e![0] === 'e' && HEX_64_RE.test(e![1]!) && REPORT_TYPES.has(e![2]!))) {
    return fail('report_tags_invalid');
  }
  return OK;
}

// kind 22242 - NIP-42 relay auth. Unchanged from the original slice:
// empty content, exactly one relay tag and one challenge tag.
function validateRelayAuth(t: NostrEventTemplate): KindPolicyResult {
  if (t.content !== '') return fail('auth_content_must_be_empty');
  const relayTags = t.tags.filter((tag) => tag[0] === 'relay');
  const challengeTags = t.tags.filter((tag) => tag[0] === 'challenge');
  if (relayTags.length !== 1 || challengeTags.length !== 1 || t.tags.length !== 2) {
    return fail('auth_tags_invalid');
  }
  if (!relayTags[0]![1]) return fail('auth_tags_invalid');
  if (!challengeTags[0]![1]) return fail('auth_tags_invalid');
  return OK;
}

// kind 24242 - Blossom authorization, exactly as Buzz's
// buildBlossomAuthHeader emits it: ["t", verb], ["x", sha256] for uploads
// only, ["expiration", near-future], ["server", authority], in that order.
function validateBlossomAuth(t: NostrEventTemplate): KindPolicyResult {
  if (t.content.length === 0 || t.content.length > 64) return fail('blossom_content_invalid');
  const tags = t.tags;
  if (tags.length < 3 || tags.length > 4) return fail('blossom_tags_invalid');
  const [verbTag, ...rest] = tags;
  if (!(verbTag!.length === 2 && verbTag![0] === 't' && (verbTag![1] === 'upload' || verbTag![1] === 'get'))) {
    return fail('blossom_tags_invalid');
  }
  const isUpload = verbTag![1] === 'upload';
  if (isUpload) {
    if (tags.length !== 4) return fail('blossom_tags_invalid');
    const x = rest[0]!;
    if (!(x.length === 2 && x[0] === 'x' && HEX_64_RE.test(x[1]!))) return fail('blossom_tags_invalid');
    rest.shift();
  } else if (tags.length !== 3) {
    return fail('blossom_tags_invalid');
  }
  const [expiration, server] = rest;
  if (!(expiration!.length === 2 && expiration![0] === 'expiration' && DECIMAL_RE.test(expiration![1]!))) {
    return fail('blossom_tags_invalid');
  }
  const expiresAt = Number(expiration![1]);
  if (expiresAt <= t.created_at || expiresAt > t.created_at + BLOSSOM_MAX_EXPIRATION_SECONDS) {
    return fail('blossom_expiration_invalid');
  }
  if (!(server!.length === 2 && server![0] === 'server' && server![1]!.length <= 255 && SERVER_AUTHORITY_RE.test(server![1]!))) {
    return fail('blossom_tags_invalid');
  }
  return OK;
}

// kind 27235 - NIP-98 HTTP auth for the supported Buzz journeys: invite
// mint/claim (POST, with payload hash) and moderation reads (GET, without).
// The `u` URL itself is bound to the granted relay in the destination check.
function validateHttpAuth(t: NostrEventTemplate): KindPolicyResult {
  if (t.content !== '') return fail('http_auth_content_must_be_empty');
  const tags = t.tags;
  if (tags.length < 3 || tags.length > 4) return fail('http_auth_tags_invalid');
  const u = tags[0]!;
  if (!(u.length === 2 && u[0] === 'u' && typeof u[1] === 'string' && u[1].length > 0 && u[1].length <= 512)) {
    return fail('http_auth_tags_invalid');
  }
  const method = tags[1]!;
  if (!(method.length === 2 && method[0] === 'method' && (method[1] === 'GET' || method[1] === 'POST'))) {
    return fail('http_auth_tags_invalid');
  }
  if (method[1] === 'POST') {
    if (tags.length !== 4) return fail('http_auth_payload_required');
    const payload = tags[2]!;
    if (!(payload.length === 2 && payload[0] === 'payload' && HEX_64_RE.test(payload[1]!))) {
      return fail('http_auth_tags_invalid');
    }
  } else if (tags.length !== 3) {
    // GET journeys never carry a payload hash.
    return fail('http_auth_payload_forbidden');
  }
  const nonce = tags[tags.length - 1]!;
  if (!(nonce.length === 2 && nonce[0] === 'nonce' && UUID_RE.test(nonce[1]!))) {
    return fail('http_auth_tags_invalid');
  }
  return OK;
}

// kind 20001 - presence: content and the single status tag carry the same
// enum value.
function validatePresence(t: NostrEventTemplate): KindPolicyResult {
  if (!PRESENCE_STATUSES.has(t.content)) return fail('presence_content_invalid');
  if (!(t.tags.length === 1 && t.tags[0]!.length === 2 && t.tags[0]![0] === 'status' && t.tags[0]![1] === t.content)) {
    return fail('presence_tags_invalid');
  }
  return OK;
}

// kind 30300 - encrypted reminder: ["d", 32-hex] + ["not_before", decimal],
// content must already be a structurally valid NIP-44 v2 payload (the
// custody nip44 endpoint produced it; this route never sees plaintext).
function validateEncryptedReminder(t: NostrEventTemplate): KindPolicyResult {
  if (!isValidNip44PayloadShape(t.content)) return fail('reminder_content_not_nip44');
  if (t.tags.length !== 2) return fail('reminder_tags_invalid');
  const [d, notBefore] = t.tags;
  if (!(d!.length === 2 && d![0] === 'd' && HEX_32_RE.test(d![1]!))) return fail('reminder_tags_invalid');
  if (!(notBefore!.length === 2 && notBefore![0] === 'not_before' && DECIMAL_RE.test(notBefore![1]!))) {
    return fail('reminder_tags_invalid');
  }
  if (Number(notBefore![1]) > Number.MAX_SAFE_INTEGER) return fail('reminder_tags_invalid');
  return OK;
}

// kind 41010 - DM open: 1..8 distinct recipient p tags, empty content.
function validateDmOpen(t: NostrEventTemplate): KindPolicyResult {
  if (t.content !== '') return fail('dm_open_content_must_be_empty');
  if (t.tags.length < 1 || t.tags.length > 8) return fail('dm_open_tags_invalid');
  const seen = new Set<string>();
  for (const tag of t.tags) {
    if (!isPubkeyTag(tag)) return fail('dm_open_tags_invalid');
    if (seen.has(tag[1]!)) return fail('dm_open_tags_invalid');
    seen.add(tag[1]!);
  }
  return OK;
}

// kinds 9030/9032 - membership add / change role: [["p"], ["role"]].
function validateMembershipWithRole(t: NostrEventTemplate): KindPolicyResult {
  if (t.content !== '') return fail('membership_content_must_be_empty');
  if (t.tags.length !== 2) return fail('membership_tags_invalid');
  const [p, role] = t.tags;
  if (!isPubkeyTag(p!)) return fail('membership_tags_invalid');
  if (!(role!.length === 2 && role![0] === 'role' && MEMBER_ROLES.has(role![1]!))) return fail('membership_tags_invalid');
  return OK;
}

// kind 9031 - membership remove: single p tag.
function validateMembershipRemove(t: NostrEventTemplate): KindPolicyResult {
  if (t.content !== '') return fail('membership_content_must_be_empty');
  if (!(t.tags.length === 1 && isPubkeyTag(t.tags[0]!))) return fail('membership_tags_invalid');
  return OK;
}

// kinds 9040-9043 - ban/unban/timeout/untimeout: ["p"] then optional
// ["expiration", epoch] then optional ["reason", note], in that order.
function validateModerationCommand(t: NostrEventTemplate): KindPolicyResult {
  if (t.content !== '') return fail('moderation_content_must_be_empty');
  if (t.tags.length < 1 || t.tags.length > 3) return fail('moderation_tags_invalid');
  if (!isPubkeyTag(t.tags[0]!)) return fail('moderation_tags_invalid');
  let index = 1;
  if (index < t.tags.length && t.tags[index]![0] === 'expiration') {
    const expiration = t.tags[index]!;
    if (!(expiration.length === 2 && DECIMAL_RE.test(expiration[1]!) && Number(expiration[1]) > 0)) {
      return fail('moderation_tags_invalid');
    }
    index += 1;
  }
  if (index < t.tags.length) {
    const reason = t.tags[index]!;
    if (!(reason.length === 2 && reason[0] === 'reason' && reason[1]!.length >= 1 && reason[1]!.length <= 512)) {
      return fail('moderation_tags_invalid');
    }
    index += 1;
  }
  if (index !== t.tags.length) return fail('moderation_tags_invalid');
  return OK;
}

// kind 9044 - resolve report: ["report"], ["status"], ["action"], optional
// ["reason"].
function validateResolveReport(t: NostrEventTemplate): KindPolicyResult {
  if (t.content !== '') return fail('moderation_content_must_be_empty');
  if (t.tags.length < 3 || t.tags.length > 4) return fail('moderation_tags_invalid');
  const [report, status, action] = t.tags;
  if (!(report!.length === 2 && report![0] === 'report' && HEX_64_RE.test(report![1]!))) return fail('moderation_tags_invalid');
  if (!(status!.length === 2 && status![0] === 'status' && RESOLVE_STATUSES.has(status![1]!))) return fail('moderation_tags_invalid');
  if (!(action!.length === 2 && action![0] === 'action' && RESOLVE_ACTIONS.has(action![1]!))) return fail('moderation_tags_invalid');
  if (t.tags.length === 4) {
    const reason = t.tags[3]!;
    if (!(reason.length === 2 && reason[0] === 'reason' && reason[1]!.length >= 1 && reason[1]!.length <= 512)) {
      return fail('moderation_tags_invalid');
    }
  }
  return OK;
}

// kind 9 - legacy channel message: generic bounds only (original PR #169
// behavior, kept for existing integrations).
function validateLegacyChannelMessage(): KindPolicyResult {
  return OK;
}

const KIND_VALIDATORS: Record<number, (t: NostrEventTemplate) => KindPolicyResult> = {
  0: validateProfileMetadata,
  7: validateReaction,
  9: validateLegacyChannelMessage,
  1984: validateReport,
  9030: validateMembershipWithRole,
  9031: validateMembershipRemove,
  9032: validateMembershipWithRole,
  9040: validateModerationCommand,
  9041: validateModerationCommand,
  9042: validateModerationCommand,
  9043: validateModerationCommand,
  9044: validateResolveReport,
  20001: validatePresence,
  22242: validateRelayAuth,
  24242: validateBlossomAuth,
  27235: validateHttpAuth,
  30300: validateEncryptedReminder,
  40002: validateChannelMessageV2,
  41010: validateDmOpen,
};

/**
 * Validate a template against its kind's payload policy. The template must
 * already have passed the generic bounds (content length, tag bounds,
 * timestamp window) enforced by the route. Unknown kinds fail closed.
 */
export function validateEventForKind(template: NostrEventTemplate): KindPolicyResult {
  const validator = KIND_VALIDATORS[template.kind];
  if (!validator) return fail('kind_not_supported');
  return validator(template);
}

/** Every kind in the capability model has a validator registered here. */
export const POLICY_KINDS: ReadonlySet<number> = new Set(Object.keys(KIND_VALIDATORS).map(Number));

/**
 * For destination-bound kinds, does this (already kind-validated) template's
 * destination correspond to the grant's approved relay? Non-destination
 * kinds always pass; destination-bound kinds fail closed when the grant has
 * no relay.
 */
export function eventDestinationMatchesGrant(
  template: NostrEventTemplate,
  grantRelayUrl: string | null | undefined,
): boolean {
  if (!DESTINATION_BOUND_NOSTR_KINDS.has(template.kind)) return true;
  if (!grantRelayUrl) return false;
  switch (template.kind) {
    case 22242: {
      const relayTag = template.tags.find((tag) => tag[0] === 'relay');
      return !!relayTag?.[1] && relayTag[1] === grantRelayUrl;
    }
    case 24242: {
      const serverTag = template.tags.find((tag) => tag[0] === 'server');
      const expected = relayServerAuthority(grantRelayUrl);
      return !!serverTag?.[1] && !!expected && serverTag[1] === expected;
    }
    case 27235: {
      const uTag = template.tags.find((tag) => tag[0] === 'u');
      const methodTag = template.tags.find((tag) => tag[0] === 'method');
      if (!uTag?.[1] || (methodTag?.[1] !== 'GET' && methodTag?.[1] !== 'POST')) return false;
      return isAllowedNip98Url(uTag[1], methodTag[1], grantRelayUrl);
    }
    default:
      return false;
  }
}
