import { describe, expect, test } from 'bun:test';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { verifyEvent, type Event as NostrToolsEvent } from 'nostr-tools/pure';
import {
  unwrapEvent as oracleUnwrapEvent,
  wrapEvent as oracleWrapEvent,
  wrapManyEvents as oracleWrapManyEvents,
} from 'nostr-tools/nip59';
import { seal } from '../src/index';
import {
  computeEventId,
  generateNostrKeypair,
  signEventWithSecretBytes,
  type SealedNostrSecret,
  type SignedNostrEvent,
} from '../src/nostr';
import { getConversationKey, nip44Encrypt } from '../src/nip44';
import {
  DM_RUMOR_KIND,
  GIFT_WRAP_KIND,
  MAX_NIP59_RECIPIENTS,
  SEAL_KIND,
  nip59UnwrapDm,
  nip59WrapDm,
  type NostrRumor,
} from '../src/nip59';

const NOW = 1754400000; // fixed "now" for deterministic timestamp-window checks
const CREATED_AT = 1754399990;
const TWO_DAYS = 2 * 24 * 60 * 60;

async function makeSealed(keypair: { secretKeyHex: string; pubkeyHex: string }): Promise<SealedNostrSecret> {
  const sealingKey = new Uint8Array(32).fill(7);
  const sealedSecret = await seal(keypair.secretKeyHex, sealingKey);
  return { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex };
}

// Adversarial fixture builders. These deliberately re-use the low-level
// primitives (never nip59WrapDm) so tests can construct wraps that the
// production wrap path refuses to produce.
function buildRumor(pubkey: string, content: string, tags: string[][], createdAt: number, kind = DM_RUMOR_KIND) {
  const template = { pubkey, created_at: createdAt, kind, tags, content };
  return { ...template, id: computeEventId(template) };
}

function buildSeal(
  senderSecret: Uint8Array,
  senderPubkey: string,
  recipientPubkey: string,
  rumorJson: string,
  overrides?: { kind?: number; tags?: string[][] },
): SignedNostrEvent {
  const conversationKey = getConversationKey(senderSecret, recipientPubkey);
  return signEventWithSecretBytes(senderSecret, {
    pubkey: senderPubkey,
    created_at: NOW - 100,
    kind: overrides?.kind ?? SEAL_KIND,
    tags: overrides?.tags ?? [],
    content: nip44Encrypt(conversationKey, rumorJson),
  });
}

function buildWrap(sealEvent: SignedNostrEvent, recipientPubkey: string): SignedNostrEvent {
  const ephemeralSecret = schnorr.utils.randomPrivateKey();
  const ephemeralPubkey = bytesToHex(schnorr.getPublicKey(ephemeralSecret));
  const conversationKey = getConversationKey(ephemeralSecret, recipientPubkey);
  return signEventWithSecretBytes(ephemeralSecret, {
    pubkey: ephemeralPubkey,
    created_at: NOW - 50,
    kind: GIFT_WRAP_KIND,
    tags: [['p', recipientPubkey]],
    content: nip44Encrypt(conversationKey, JSON.stringify(sealEvent)),
  });
}

describe('nip59WrapDm output structure', () => {
  test('returns recipients+1 wraps with the self-wrap first', async () => {
    const sender = generateNostrKeypair();
    const b = generateNostrKeypair();
    const c = generateNostrKeypair();
    const sealed = await makeSealed(sender);

    const wraps = await nip59WrapDm(sealed, {
      content: 'hello group',
      recipients: [b.pubkeyHex, c.pubkeyHex],
      createdAt: CREATED_AT,
      now: NOW,
    });

    expect(wraps.length).toBe(3);
    expect(wraps[0]!.tags[0]![1]).toBe(sender.pubkeyHex);
    expect(wraps[1]!.tags[0]![1]).toBe(b.pubkeyHex);
    expect(wraps[2]!.tags[0]![1]).toBe(c.pubkeyHex);
  });

  test('every wrap is kind 1059 with one p tag, a valid sig from a distinct ephemeral key, and a backdated timestamp', async () => {
    const sender = generateNostrKeypair();
    const b = generateNostrKeypair();
    const c = generateNostrKeypair();
    const sealed = await makeSealed(sender);

    const wraps = await nip59WrapDm(sealed, {
      content: 'structural checks',
      recipients: [b.pubkeyHex, c.pubkeyHex],
      createdAt: CREATED_AT,
      now: NOW,
    });

    const wrapPubkeys = new Set<string>();
    for (const wrap of wraps) {
      expect(wrap.kind).toBe(GIFT_WRAP_KIND);
      expect(wrap.tags.length).toBe(1);
      expect(wrap.tags[0]![0]).toBe('p');
      // Independent Schnorr verification via nostr-tools.
      expect(verifyEvent(wrap as NostrToolsEvent)).toBe(true);
      // Ephemeral signer: never the sender, never a recipient, never reused.
      expect(wrap.pubkey).not.toBe(sender.pubkeyHex);
      expect(wrap.pubkey).not.toBe(b.pubkeyHex);
      expect(wrap.pubkey).not.toBe(c.pubkeyHex);
      wrapPubkeys.add(wrap.pubkey);
      // NIP-59 backdating window: (now - 2 days, now].
      expect(wrap.created_at).toBeLessThanOrEqual(NOW);
      expect(wrap.created_at).toBeGreaterThanOrEqual(NOW - TWO_DAYS);
    }
    expect(wrapPubkeys.size).toBe(wraps.length);
  });
});

describe('nip59WrapDm oracle interop (our wraps -> nostr-tools unwrap)', () => {
  test('each wrap unwraps with the recipient secret to the identical kind-14 rumor', async () => {
    const sender = generateNostrKeypair();
    const b = generateNostrKeypair();
    const c = generateNostrKeypair();
    const sealed = await makeSealed(sender);
    const content = 'oracle-visible dm content';

    const wraps = await nip59WrapDm(sealed, {
      content,
      recipients: [b.pubkeyHex, c.pubkeyHex],
      createdAt: CREATED_AT,
      now: NOW,
    });

    const secrets = [sender.secretKeyHex, b.secretKeyHex, c.secretKeyHex];
    const rumors = wraps.map((wrap, i) =>
      oracleUnwrapEvent(wrap as NostrToolsEvent, hexToBytes(secrets[i]!)),
    );

    for (const rumor of rumors) {
      expect(rumor.kind).toBe(DM_RUMOR_KIND);
      expect(rumor.content).toBe(content);
      expect(rumor.created_at).toBe(CREATED_AT); // real send time, not backdated
      expect(rumor.pubkey).toBe(sender.pubkeyHex);
      // Recipients are p-tagged; the sender's self-wrap is implicit, not tagged.
      expect(rumor.tags).toEqual([['p', b.pubkeyHex], ['p', c.pubkeyHex]]);
    }
    // Identical rumor (same id) across the self-wrap and every recipient wrap.
    expect(new Set(rumors.map((r) => r.id)).size).toBe(1);
    expect(rumors[0]!.id).toBe(
      computeEventId({
        pubkey: sender.pubkeyHex,
        created_at: CREATED_AT,
        kind: DM_RUMOR_KIND,
        tags: [['p', b.pubkeyHex], ['p', c.pubkeyHex]],
        content,
      }),
    );
  });
});

describe('nip59UnwrapDm oracle interop (nostr-tools wraps -> our unwrap)', () => {
  test('unwraps a wrap produced by nostr-tools wrapEvent', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealedRecipient = await makeSealed(recipient);

    const wrap = oracleWrapEvent(
      {
        kind: DM_RUMOR_KIND,
        content: 'from the oracle wrapper',
        created_at: CREATED_AT,
        tags: [['p', recipient.pubkeyHex]],
      },
      hexToBytes(sender.secretKeyHex),
      recipient.pubkeyHex,
    );

    const rumor = await nip59UnwrapDm(sealedRecipient, wrap as unknown as SignedNostrEvent);
    expect(rumor.kind).toBe(DM_RUMOR_KIND);
    expect(rumor.content).toBe('from the oracle wrapper');
    expect(rumor.created_at).toBe(CREATED_AT);
    expect(rumor.pubkey).toBe(sender.pubkeyHex);
    expect(rumor.tags).toEqual([['p', recipient.pubkeyHex]]);
  });

  test('unwraps wraps produced by nostr-tools wrapManyEvents (self and recipient)', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealedSender = await makeSealed(sender);
    const sealedRecipient = await makeSealed(recipient);

    // nostr-tools also emits the self-wrap first.
    const wraps = oracleWrapManyEvents(
      {
        kind: DM_RUMOR_KIND,
        content: 'group dm via oracle',
        created_at: CREATED_AT,
        tags: [['p', recipient.pubkeyHex]],
      },
      hexToBytes(sender.secretKeyHex),
      [recipient.pubkeyHex],
    );
    expect(wraps.length).toBe(2);

    const selfRumor = await nip59UnwrapDm(sealedSender, wraps[0] as unknown as SignedNostrEvent);
    const recipientRumor = await nip59UnwrapDm(sealedRecipient, wraps[1] as unknown as SignedNostrEvent);
    expect(selfRumor.id).toBe(recipientRumor.id);
    expect(selfRumor.content).toBe('group dm via oracle');
    expect(recipientRumor.pubkey).toBe(sender.pubkeyHex);
  });
});

describe('nip59UnwrapDm failure matrix', () => {
  async function wrapForRecipient() {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealedSender = await makeSealed(sender);
    const sealedRecipient = await makeSealed(recipient);
    const [, wrap] = await nip59WrapDm(sealedSender, {
      content: 'failure matrix baseline',
      recipients: [recipient.pubkeyHex],
      createdAt: CREATED_AT,
      now: NOW,
    });
    return { sender, recipient, sealedSender, sealedRecipient, wrap: wrap! };
  }

  test('wrap addressed to someone else -> nip59_wrong_recipient', async () => {
    const { wrap } = await wrapForRecipient();
    const bystander = generateNostrKeypair();
    const sealedBystander = await makeSealed(bystander);
    await expect(nip59UnwrapDm(sealedBystander, wrap)).rejects.toThrow(/nip59_wrong_recipient/);
  });

  test('tampered wrap content -> signature verification failure', async () => {
    const { sealedRecipient, wrap } = await wrapForRecipient();
    const decoded = Buffer.from(wrap.content, 'base64');
    decoded[40] = decoded[40]! ^ 0x01;
    const tampered = { ...wrap, content: decoded.toString('base64') };
    await expect(nip59UnwrapDm(sealedRecipient, tampered)).rejects.toThrow(/nip59_invalid_wrap/);
  });

  test('tampered wrap sig -> signature verification failure', async () => {
    const { sealedRecipient, wrap } = await wrapForRecipient();
    const badSigByte = wrap.sig.slice(0, 126) + (wrap.sig.slice(126) === 'ff' ? '00' : 'ff');
    await expect(nip59UnwrapDm(sealedRecipient, { ...wrap, sig: badSigByte })).rejects.toThrow(
      /nip59_invalid_wrap/,
    );
  });

  test('outer kind other than 1059 is rejected', async () => {
    const { sealedRecipient, wrap } = await wrapForRecipient();
    await expect(nip59UnwrapDm(sealedRecipient, { ...wrap, kind: 1058 })).rejects.toThrow(/nip59_invalid_wrap/);
  });

  test('seal with non-empty tags -> nip59_invalid_seal', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealedRecipient = await makeSealed(recipient);
    const senderSecret = hexToBytes(sender.secretKeyHex);
    const rumor = buildRumor(sender.pubkeyHex, 'hi', [['p', recipient.pubkeyHex]], CREATED_AT);
    const sealEvent = buildSeal(senderSecret, sender.pubkeyHex, recipient.pubkeyHex, JSON.stringify(rumor), {
      tags: [['p', recipient.pubkeyHex]],
    });
    const wrap = buildWrap(sealEvent, recipient.pubkeyHex);
    await expect(nip59UnwrapDm(sealedRecipient, wrap)).rejects.toThrow(/nip59_invalid_seal/);
  });

  test('seal with a wrong kind -> nip59_invalid_seal', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealedRecipient = await makeSealed(recipient);
    const senderSecret = hexToBytes(sender.secretKeyHex);
    const rumor = buildRumor(sender.pubkeyHex, 'hi', [['p', recipient.pubkeyHex]], CREATED_AT);
    const sealEvent = buildSeal(senderSecret, sender.pubkeyHex, recipient.pubkeyHex, JSON.stringify(rumor), {
      kind: 12,
    });
    const wrap = buildWrap(sealEvent, recipient.pubkeyHex);
    await expect(nip59UnwrapDm(sealedRecipient, wrap)).rejects.toThrow(/nip59_invalid_seal/);
  });

  test('seal signer different from rumor author (spoofed sender) -> nip59_sender_mismatch', async () => {
    const sender = generateNostrKeypair(); // signs the seal
    const spoofed = generateNostrKeypair(); // claimed rumor author
    const recipient = generateNostrKeypair();
    const sealedRecipient = await makeSealed(recipient);
    const senderSecret = hexToBytes(sender.secretKeyHex);
    const rumor = buildRumor(spoofed.pubkeyHex, 'i am not who i say i am', [['p', recipient.pubkeyHex]], CREATED_AT);
    const sealEvent = buildSeal(senderSecret, sender.pubkeyHex, recipient.pubkeyHex, JSON.stringify(rumor));
    const wrap = buildWrap(sealEvent, recipient.pubkeyHex);
    await expect(nip59UnwrapDm(sealedRecipient, wrap)).rejects.toThrow(/nip59_sender_mismatch/);
  });

  test('rumor whose id does not match its contents is rejected', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealedRecipient = await makeSealed(recipient);
    const senderSecret = hexToBytes(sender.secretKeyHex);
    const rumor = buildRumor(sender.pubkeyHex, 'original content', [['p', recipient.pubkeyHex]], CREATED_AT);
    // Mutate the content after the id was computed - a forged rumor body.
    const forged: NostrRumor = { ...rumor, content: 'swapped content' };
    const sealEvent = buildSeal(senderSecret, sender.pubkeyHex, recipient.pubkeyHex, JSON.stringify(forged));
    const wrap = buildWrap(sealEvent, recipient.pubkeyHex);
    await expect(nip59UnwrapDm(sealedRecipient, wrap)).rejects.toThrow(/nip59_invalid_rumor/);
  });

  test('rumor kind other than 14 is rejected', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealedRecipient = await makeSealed(recipient);
    const senderSecret = hexToBytes(sender.secretKeyHex);
    const rumor = buildRumor(sender.pubkeyHex, 'hi', [['p', recipient.pubkeyHex]], CREATED_AT, 1);
    const sealEvent = buildSeal(senderSecret, sender.pubkeyHex, recipient.pubkeyHex, JSON.stringify(rumor));
    const wrap = buildWrap(sealEvent, recipient.pubkeyHex);
    await expect(nip59UnwrapDm(sealedRecipient, wrap)).rejects.toThrow(/nip59_invalid_rumor/);
  });

  test('rumor content larger than maxContentLength option is rejected', async () => {
    const { sealedRecipient, wrap } = await wrapForRecipient();
    await expect(nip59UnwrapDm(sealedRecipient, wrap, { maxContentLength: 4 })).rejects.toThrow(
      /nip59_invalid_rumor/,
    );
    // Sanity: the same wrap unwraps fine with the default bound.
    const rumor = await nip59UnwrapDm(sealedRecipient, wrap);
    expect(rumor.content).toBe('failure matrix baseline');
  });
});

describe('nip59WrapDm input validation', () => {
  test('zero recipients rejected', async () => {
    const sender = generateNostrKeypair();
    const sealed = await makeSealed(sender);
    await expect(
      nip59WrapDm(sealed, { content: 'x', recipients: [], createdAt: CREATED_AT, now: NOW }),
    ).rejects.toThrow(/nip59_invalid_recipients/);
  });

  test('more than MAX_NIP59_RECIPIENTS distinct recipients rejected', async () => {
    const sender = generateNostrKeypair();
    const sealed = await makeSealed(sender);
    const recipients = Array.from({ length: MAX_NIP59_RECIPIENTS + 1 }, () => generateNostrKeypair().pubkeyHex);
    await expect(
      nip59WrapDm(sealed, { content: 'x', recipients, createdAt: CREATED_AT, now: NOW }),
    ).rejects.toThrow(/nip59_invalid_recipients/);
  });

  test('invalid recipient hex rejected', async () => {
    const sender = generateNostrKeypair();
    const sealed = await makeSealed(sender);
    await expect(
      nip59WrapDm(sealed, { content: 'x', recipients: ['not-a-pubkey'], createdAt: CREATED_AT, now: NOW }),
    ).rejects.toThrow(/nip59_invalid_recipients/);
    await expect(
      nip59WrapDm(sealed, {
        content: 'x',
        recipients: [generateNostrKeypair().pubkeyHex.slice(0, 63)],
        createdAt: CREATED_AT,
        now: NOW,
      }),
    ).rejects.toThrow(/nip59_invalid_recipients/);
  });

  test('sender pubkey in the recipients list rejected (self-wrap is implicit)', async () => {
    const sender = generateNostrKeypair();
    const other = generateNostrKeypair();
    const sealed = await makeSealed(sender);
    await expect(
      nip59WrapDm(sealed, {
        content: 'x',
        recipients: [other.pubkeyHex, sender.pubkeyHex],
        createdAt: CREATED_AT,
        now: NOW,
      }),
    ).rejects.toThrow(/nip59_invalid_recipients/);
  });

  test('duplicate recipients are deduped (including case-insensitive duplicates)', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealed = await makeSealed(sender);
    const wraps = await nip59WrapDm(sealed, {
      content: 'deduped',
      recipients: [recipient.pubkeyHex, recipient.pubkeyHex, recipient.pubkeyHex.toUpperCase()],
      createdAt: CREATED_AT,
      now: NOW,
    });
    expect(wraps.length).toBe(2); // self-wrap + one recipient
    expect(wraps[1]!.tags[0]![1]).toBe(recipient.pubkeyHex);
  });

  test('non-integer or non-positive createdAt rejected', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealed = await makeSealed(sender);
    for (const createdAt of [1.5, 0, -1, Number.NaN]) {
      await expect(
        nip59WrapDm(sealed, { content: 'x', recipients: [recipient.pubkeyHex], createdAt, now: NOW }),
      ).rejects.toThrow(/nip59_invalid_created_at/);
    }
  });

  test('empty or oversized content rejected', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealed = await makeSealed(sender);
    await expect(
      nip59WrapDm(sealed, { content: '', recipients: [recipient.pubkeyHex], createdAt: CREATED_AT, now: NOW }),
    ).rejects.toThrow(/nip59_invalid_content/);
    await expect(
      nip59WrapDm(sealed, {
        content: 'a'.repeat(65536),
        recipients: [recipient.pubkeyHex],
        createdAt: CREATED_AT,
        now: NOW,
      }),
    ).rejects.toThrow(/nip59_invalid_content/);
  });
});
