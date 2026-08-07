// NIP-59 gift wrap inside the custody boundary (Buzz direct messages).
//
// The whole rumor -> seal -> gift-wrap pipeline runs inside this module so
// the custodied secret, the per-recipient conversation keys, and the
// per-wrap ephemeral keys never leave it. Matches the construction Buzz
// gets from nostr-tools' nip59 (`wrapManyEvents`): an unsigned kind-14
// rumor, a kind-13 seal signed by the sender, and a kind-1059 wrap signed
// by a fresh ephemeral key per recipient - with the self-wrap emitted
// first so the sender's own client sees the conversation.
//
// Seal and wrap timestamps are randomized up to two days into the past per
// NIP-59, which is why these events are generated here rather than pushed
// through the sign-event timestamp window. The rumor keeps the caller's
// real send time, exactly like Buzz's local signer path.
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/curves/abstract/utils';
import { randomInt } from 'crypto';
import {
  computeEventId,
  signEventWithSecretBytes,
  verifyNostrEvent,
  withUnsealedNostrSecret,
  type SealedNostrSecret,
  type SignedNostrEvent,
} from './nostr';
import { getConversationKey, nip44Decrypt, nip44Encrypt } from './nip44';

export const DM_RUMOR_KIND = 14;
export const SEAL_KIND = 13;
export const GIFT_WRAP_KIND = 1059;

/** Custody-boundary ceiling; API policy narrows to Buzz's 8-recipient DMs. */
export const MAX_NIP59_RECIPIENTS = 16;
const MAX_RUMOR_TAGS = 32;
const MAX_RUMOR_TAG_VALUES = 16;
const MAX_RUMOR_TAG_VALUE_LENGTH = 512;
const MAX_RUMOR_CONTENT_LENGTH = 65535;
const TWO_DAYS_SECONDS = 2 * 24 * 60 * 60;

const PUBKEY_HEX_RE = /^[0-9a-f]{64}$/;

/** An unsealed kind-14 DM rumor: id-addressed but deliberately unsigned. */
export interface NostrRumor {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

function randomPastTimestamp(now: number): number {
  return now - randomInt(0, TWO_DAYS_SECONDS);
}

function normalizeRecipients(recipients: string[], ownPubkeyHex: string): string[] {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error('nip59_invalid_recipients: at least one recipient is required');
  }
  const unique = [...new Set(recipients.map((r) => String(r).trim().toLowerCase()))];
  if (unique.length > MAX_NIP59_RECIPIENTS) {
    throw new Error('nip59_invalid_recipients: too many recipients');
  }
  for (const recipient of unique) {
    if (!PUBKEY_HEX_RE.test(recipient)) {
      throw new Error('nip59_invalid_recipients: recipient must be 64 hex characters');
    }
    if (recipient === ownPubkeyHex) {
      throw new Error('nip59_invalid_recipients: the sender self-wrap is implicit');
    }
  }
  return unique;
}

function encryptTo(
  secretBytes: Uint8Array,
  recipientPubkeyHex: string,
  plaintext: string,
): string {
  const conversationKey = getConversationKey(secretBytes, recipientPubkeyHex);
  try {
    return nip44Encrypt(conversationKey, plaintext);
  } finally {
    conversationKey.fill(0);
  }
}

function decryptFrom(
  secretBytes: Uint8Array,
  peerPubkeyHex: string,
  payload: string,
): string {
  const conversationKey = getConversationKey(secretBytes, peerPubkeyHex);
  try {
    return nip44Decrypt(conversationKey, payload);
  } finally {
    conversationKey.fill(0);
  }
}

function wrapSealForRecipient(
  seal: SignedNostrEvent,
  recipientPubkeyHex: string,
  now: number,
): SignedNostrEvent {
  const ephemeralSecret = schnorr.utils.randomPrivateKey();
  try {
    const ephemeralPubkey = bytesToHex(schnorr.getPublicKey(ephemeralSecret));
    const content = encryptTo(ephemeralSecret, recipientPubkeyHex, JSON.stringify(seal));
    return signEventWithSecretBytes(ephemeralSecret, {
      pubkey: ephemeralPubkey,
      created_at: randomPastTimestamp(now),
      kind: GIFT_WRAP_KIND,
      tags: [['p', recipientPubkeyHex]],
      content,
    });
  } finally {
    ephemeralSecret.fill(0);
  }
}

/**
 * Build the full set of gift wraps for one DM: the sender's self-wrap
 * first, then one wrap per recipient (`wraps.length === recipients + 1`).
 * Every wrap carries its own seal, ephemeral key, and randomized
 * timestamps; all decrypt to the identical rumor id.
 */
export async function nip59WrapDm(
  sealed: SealedNostrSecret,
  opts: { content: string; recipients: string[]; createdAt: number; now?: number },
): Promise<SignedNostrEvent[]> {
  const ownPubkeyHex = sealed.expectedPubkeyHex.trim().toLowerCase();
  const recipients = normalizeRecipients(opts.recipients, ownPubkeyHex);
  if (typeof opts.content !== 'string' || opts.content.length === 0 || opts.content.length > MAX_RUMOR_CONTENT_LENGTH) {
    throw new Error('nip59_invalid_content');
  }
  if (!Number.isInteger(opts.createdAt) || opts.createdAt <= 0) {
    throw new Error('nip59_invalid_created_at');
  }
  const now = opts.now ?? Math.floor(Date.now() / 1000);

  return withUnsealedNostrSecret(sealed, (secretBytes) => {
    const rumorTemplate = {
      pubkey: ownPubkeyHex,
      created_at: opts.createdAt,
      kind: DM_RUMOR_KIND,
      tags: recipients.map((recipient) => ['p', recipient]),
      content: opts.content,
    };
    const rumor: NostrRumor = { ...rumorTemplate, id: computeEventId(rumorTemplate) };
    const rumorJson = JSON.stringify(rumor);

    const targets = [ownPubkeyHex, ...recipients];
    return targets.map((target) => {
      const seal = signEventWithSecretBytes(secretBytes, {
        pubkey: ownPubkeyHex,
        created_at: randomPastTimestamp(now),
        kind: SEAL_KIND,
        tags: [],
        content: encryptTo(secretBytes, target, rumorJson),
      });
      return wrapSealForRecipient(seal, target, now);
    });
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isBoundedRumorTags(value: unknown): value is string[][] {
  if (!Array.isArray(value) || value.length > MAX_RUMOR_TAGS) return false;
  return value.every(
    (tag) =>
      Array.isArray(tag)
      && tag.length > 0
      && tag.length <= MAX_RUMOR_TAG_VALUES
      && tag.every((item) => typeof item === 'string' && item.length <= MAX_RUMOR_TAG_VALUE_LENGTH),
  );
}

function parseSignedEventJson(json: string, expectedKind: number, errorCode: string): SignedNostrEvent {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error(errorCode);
  }
  if (
    !isRecord(parsed)
    || parsed.kind !== expectedKind
    || typeof parsed.pubkey !== 'string'
    || !PUBKEY_HEX_RE.test(parsed.pubkey.toLowerCase())
    || typeof parsed.id !== 'string'
    || typeof parsed.sig !== 'string'
    || !Number.isInteger(parsed.created_at)
    || typeof parsed.content !== 'string'
    || !Array.isArray(parsed.tags)
  ) {
    throw new Error(errorCode);
  }
  return parsed as unknown as SignedNostrEvent;
}

/**
 * Unwrap a kind-1059 gift wrap addressed to this key and return only the
 * validated inner rumor. Verifies, in order: the outer wrap's structure,
 * recipient binding, and Schnorr signature; the seal's kind-13 structure,
 * empty tags, and signature; and the rumor's kind-14 structure, sender
 * consistency (`seal.pubkey === rumor.pubkey` - the anti-spoof check), and
 * recomputed event id. No timestamp window applies: gift wraps are
 * backdated by design and may be fetched from arbitrary relay history.
 */
export async function nip59UnwrapDm(
  sealed: SealedNostrSecret,
  wrap: SignedNostrEvent,
  opts?: { maxContentLength?: number },
): Promise<NostrRumor> {
  const ownPubkeyHex = sealed.expectedPubkeyHex.trim().toLowerCase();
  const maxContentLength = opts?.maxContentLength ?? MAX_RUMOR_CONTENT_LENGTH;

  if (!isRecord(wrap) || wrap.kind !== GIFT_WRAP_KIND) {
    throw new Error('nip59_invalid_wrap: outer event is not a gift wrap');
  }
  if (typeof wrap.pubkey !== 'string' || !PUBKEY_HEX_RE.test(wrap.pubkey.toLowerCase())) {
    throw new Error('nip59_invalid_wrap: malformed wrap pubkey');
  }
  if (
    !Array.isArray(wrap.tags)
    || wrap.tags.length !== 1
    || !Array.isArray(wrap.tags[0])
    || wrap.tags[0]![0] !== 'p'
    || typeof wrap.tags[0]![1] !== 'string'
    || wrap.tags[0]!.length > 3
    || !wrap.tags[0]!.every((item) => typeof item === 'string' && item.length <= MAX_RUMOR_TAG_VALUE_LENGTH)
  ) {
    throw new Error('nip59_invalid_wrap: wrap must carry exactly one recipient tag');
  }
  if (wrap.tags[0]![1]!.toLowerCase() !== ownPubkeyHex) {
    throw new Error('nip59_wrong_recipient: gift wrap is not addressed to this key');
  }
  if (typeof wrap.content !== 'string') {
    throw new Error('nip59_invalid_wrap: malformed wrap content');
  }
  if (!verifyNostrEvent(wrap)) {
    throw new Error('nip59_invalid_wrap: wrap signature verification failed');
  }

  return withUnsealedNostrSecret(sealed, (secretBytes) => {
    const seal = parseSignedEventJson(
      decryptFrom(secretBytes, wrap.pubkey.toLowerCase(), wrap.content),
      SEAL_KIND,
      'nip59_invalid_seal',
    );
    if (seal.tags.length !== 0) {
      throw new Error('nip59_invalid_seal');
    }
    if (!verifyNostrEvent(seal)) {
      throw new Error('nip59_invalid_seal: seal signature verification failed');
    }

    const sealPubkey = seal.pubkey.toLowerCase();
    let parsedRumor: unknown;
    try {
      parsedRumor = JSON.parse(decryptFrom(secretBytes, sealPubkey, seal.content));
    } catch {
      throw new Error('nip59_invalid_rumor');
    }
    if (
      !isRecord(parsedRumor)
      || parsedRumor.kind !== DM_RUMOR_KIND
      || typeof parsedRumor.pubkey !== 'string'
      || typeof parsedRumor.id !== 'string'
      || !Number.isInteger(parsedRumor.created_at)
      || (parsedRumor.created_at as number) <= 0
      || typeof parsedRumor.content !== 'string'
      || (parsedRumor.content as string).length > maxContentLength
      || !isBoundedRumorTags(parsedRumor.tags)
    ) {
      throw new Error('nip59_invalid_rumor');
    }
    const rumorPubkey = (parsedRumor.pubkey as string).toLowerCase();
    if (rumorPubkey !== sealPubkey) {
      throw new Error('nip59_sender_mismatch: seal signer does not match rumor author');
    }
    const rumorTemplate = {
      pubkey: rumorPubkey,
      created_at: parsedRumor.created_at as number,
      kind: DM_RUMOR_KIND,
      tags: parsedRumor.tags as string[][],
      content: parsedRumor.content as string,
    };
    if (computeEventId(rumorTemplate) !== (parsedRumor.id as string).toLowerCase()) {
      throw new Error('nip59_invalid_rumor: rumor id does not match its contents');
    }
    return { ...rumorTemplate, id: (parsedRumor.id as string).toLowerCase() };
  });
}
