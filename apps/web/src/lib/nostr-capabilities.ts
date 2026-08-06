// The Nostr custody capability model, as the approval widget displays it.
//
// Deliberately mirrored from packages/tee/src/nostr-capabilities.ts rather
// than imported: the web app is a browser deployable and cannot depend on
// the TEE package (node-only crypto/dstack dependencies). The contract test
// tests/nostr-capability-matrix.test.ts asserts these mirrors stay in sync
// with the authoritative model.

export const NOSTR_CAPABILITY_VERSION = 2;

export type NostrOperationName = 'nip44_encrypt' | 'nip44_decrypt' | 'nip59_wrap' | 'nip59_unwrap';

/**
 * Consent copy per signable kind. Every supported kind has an entry; the
 * matrix test fails if the capability model and this map drift apart.
 * `sensitive` marks capabilities whose consent copy warrants an explicit
 * caution line in the approval card.
 */
export const NOSTR_KIND_COPY: Record<number, { title: string; description: string; sensitive?: boolean }> = {
  0: { title: 'Update your profile', description: 'Publish your display name, avatar, and bio.' },
  7: { title: 'React to messages', description: 'Add emoji reactions to channel messages.' },
  9: { title: 'Send channel messages (legacy)', description: 'Post messages to public channels.' },
  1984: { title: 'Report content', description: 'File moderation reports about messages or users.' },
  9030: { title: 'Add community members', description: 'Add members to a community you help run.', sensitive: true },
  9031: { title: 'Remove community members', description: 'Remove members from a community you help run.', sensitive: true },
  9032: { title: 'Change member roles', description: 'Promote or demote community members.', sensitive: true },
  9040: { title: 'Ban users', description: 'Ban users from a community as a moderator.', sensitive: true },
  9041: { title: 'Unban users', description: 'Lift bans as a moderator.', sensitive: true },
  9042: { title: 'Time out users', description: 'Temporarily mute users as a moderator.', sensitive: true },
  9043: { title: 'Lift timeouts', description: 'End temporary mutes as a moderator.', sensitive: true },
  9044: { title: 'Resolve reports', description: 'Close or act on moderation reports.', sensitive: true },
  20001: { title: 'Share your presence', description: 'Show whether you are online, away, or offline.' },
  22242: { title: 'Authenticate to the relay', description: 'Prove your identity to the community relay.' },
  24242: { title: 'Upload and view media', description: 'Authorize uploads and downloads of attachments.' },
  27235: { title: 'Use invites and moderation tools', description: 'Authorize invite and moderation requests to the community server.' },
  30300: { title: 'Save encrypted reminders', description: 'Store reminders that only you can read.' },
  40002: { title: 'Send channel messages', description: 'Post messages and attachments to channels.' },
  41010: { title: 'Start direct messages', description: 'Open direct message conversations.' },
};

/** Consent copy per named crypto operation. */
export const NOSTR_OPERATION_COPY: Record<NostrOperationName, { title: string; description: string; sensitive?: boolean }> = {
  nip44_encrypt: {
    title: 'Encrypt private notes',
    description: 'Encrypt reminders so only you can read them. The key never leaves OpenKey.',
  },
  nip44_decrypt: {
    title: 'Decrypt private data',
    description: 'Decrypt your reminders and messages from your agents. This app sees the decrypted text.',
    sensitive: true,
  },
  nip59_wrap: {
    title: 'Send private messages',
    description: 'Seal direct messages so only their recipients can read them.',
  },
  nip59_unwrap: {
    title: 'Read private messages',
    description: 'Open direct messages sent to you. This app sees the message text.',
    sensitive: true,
  },
};

export const SUPPORTED_NOSTR_KINDS: ReadonlySet<number> = new Set(
  Object.keys(NOSTR_KIND_COPY).map(Number),
);

export const SUPPORTED_NOSTR_OPERATIONS: readonly NostrOperationName[] = [
  'nip44_encrypt',
  'nip44_decrypt',
  'nip59_wrap',
  'nip59_unwrap',
];

/** Kinds whose grant must be bound to a specific relay destination. */
export const DESTINATION_BOUND_NOSTR_KINDS: ReadonlySet<number> = new Set([22242, 24242, 27235]);

export function isSupportedNostrOperation(value: unknown): value is NostrOperationName {
  return typeof value === 'string' && (SUPPORTED_NOSTR_OPERATIONS as readonly string[]).includes(value);
}
