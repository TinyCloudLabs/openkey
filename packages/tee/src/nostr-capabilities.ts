// The versioned Nostr custody capability model.
//
// A capability is either an event kind the custody boundary will sign, or a
// named cryptographic operation it will perform without ever releasing key
// material. API routes enforce this model against incoming requests; grants
// persist subsets of it; the SDK and approval widget mirror it for display.
// The mirror copies cannot import this package (separate deployables), so
// tests/nostr-capability-matrix.test.ts asserts they stay in sync.

/**
 * Version 1 supported exactly kinds 9 and 22242. Version 2 covers the
 * complete Buzz web client mutation/encryption matrix plus the NIP-44 and
 * NIP-59 operations Buzz needs for reminders, observer frames, and DMs.
 */
export const NOSTR_CAPABILITY_VERSION = 2;

/**
 * Event kinds the signing boundary supports, with the Buzz journey each one
 * serves. Every kind has a purpose-specific payload validator on the API
 * side (apps/api/src/services/nostr-event-policy.ts); being listed here is
 * necessary but not sufficient for a template to be signed.
 */
export const SUPPORTED_NOSTR_KINDS: ReadonlySet<number> = new Set([
  0, // profile metadata (NIP-01)
  7, // reaction (NIP-25)
  9, // legacy channel message (kept for existing integrations)
  1984, // content report (NIP-56)
  9001, // channel membership: remove a member from a channel (NIP-29)
  9002, // channel metadata: edit name/about/visibility (NIP-29)
  9007, // channel creation: the relay provisions kind-39000 from this (NIP-29)
  9021, // channel join request (NIP-29)
  9030, // relay membership: add member
  9031, // relay membership: remove member
  9032, // relay membership: change role
  9040, // moderation: ban
  9041, // moderation: unban
  9042, // moderation: timeout
  9043, // moderation: untimeout
  9044, // moderation: resolve report
  20001, // presence status (ephemeral)
  22242, // relay auth (NIP-42)
  24242, // Blossom media authorization
  27235, // HTTP authorization (NIP-98)
  30300, // encrypted reminder (addressable, NIP-44 self-encrypted content)
  40002, // channel message v2
  41010, // DM conversation open
]);

/**
 * Named cryptographic operations the custody boundary performs. Each is
 * purpose-bound and independently authorized per grant; none ever returns
 * secret-key material or a reusable conversation key.
 */
export const SUPPORTED_NOSTR_OPERATIONS = [
  'nip44_encrypt', // encrypt-to-self only (Buzz reminders)
  'nip44_decrypt', // decrypt from self or a peer (reminders, observer frames)
  'nip59_wrap', // gift-wrap a kind-14 DM rumor for its recipients
  'nip59_unwrap', // unwrap a kind-1059 gift wrap addressed to this key
] as const;

export type NostrOperation = (typeof SUPPORTED_NOSTR_OPERATIONS)[number];

export function isNostrOperation(value: unknown): value is NostrOperation {
  return (
    typeof value === 'string'
    && (SUPPORTED_NOSTR_OPERATIONS as readonly string[]).includes(value)
  );
}

/**
 * Kinds whose signed output authenticates the key against a specific
 * destination (a relay, a Blossom server, an HTTP endpoint). Grants for
 * these kinds must carry a relayUrl, and the event's own destination must
 * correspond to it - a grant approved for one Buzz relay must never
 * authorize a challenge or token for an unrelated destination.
 */
export const DESTINATION_BOUND_NOSTR_KINDS: ReadonlySet<number> = new Set([
  22242, // event `relay` tag must equal the granted relay URL exactly
  24242, // event `server` tag must equal the granted relay's host authority
  27235, // event `u` tag must live on the granted relay's http(s) origin
]);
