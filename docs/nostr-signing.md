# Managed Nostr signing

OpenKey can hold one Nostr identity per user and perform a narrowly bounded
set of cryptographic operations without exposing the secret key to the
integrating application: signing an explicit allowlist of NIP-01 event kinds,
NIP-44 v2 encryption/decryption, and NIP-59 gift wrapping/unwrapping. The
Nostr path uses BIP-340 Schnorr signatures and is separate from OpenKey's
Ethereum/ECDSA keys and signing routes.

## Capability model (version 2)

A grant scopes one client origin to a subset of **signable event kinds** plus
a subset of **named crypto operations**. Version 1 supported only kinds `9`
and `22242`; version 2 covers the complete Buzz web client matrix. The
authoritative model lives in `packages/tee/src/nostr-capabilities.ts`, and
`tests/nostr-capability-matrix.test.ts` maps every named Buzz journey to its
capabilities so missing support is mechanically obvious.

| Buzz journey | Kinds | Operations |
|---|---|---|
| Profile metadata | 0 | |
| Reactions | 7 | |
| Channel messages | 9 (legacy), 40002 | |
| Content reports | 1984 | |
| Relay auth (NIP-42) | 22242 | |
| Blossom media authorization | 24242 | |
| HTTP auth for invites + moderation reads (NIP-98) | 27235 | |
| Presence | 20001 | |
| Encrypted reminders | 30300 | `nip44_encrypt`, `nip44_decrypt` |
| DM open | 41010 | |
| Direct messages (NIP-59) | | `nip59_wrap`, `nip59_unwrap` |
| Agent observer frames | | `nip44_decrypt` |
| Relay membership administration | 9030, 9031, 9032 | |
| Moderation | 9040, 9041, 9042, 9043, 9044 | |

Every kind has a purpose-specific payload validator
(`apps/api/src/services/nostr-event-policy.ts`) that pins allowed/required
tags, cardinality, value syntax, and content shape to what Buzz actually
produces - being on the allowlist is necessary but not sufficient. Kind `9`
keeps its original generic bounds for existing integrations.

## Destination binding

Kinds whose signature authenticates the key against a destination are bound
to the grant's approved relay (`apps/api/src/services/nostr-destinations.ts`
mirrors Buzz's own URL derivations):

- `22242`: the event's `relay` tag must equal the granted relay URL exactly.
- `24242`: the event's `server` tag must equal the relay's host authority
  (ws(s) mapped to http(s), lowercase host, default ports stripped).
- `27235`: the event's `u` URL must live on the relay's http(s) surface and
  match a supported journey - invite mint/claim (`POST` with a payload hash,
  the relay URL's path prefix kept) or moderation reads (`GET` without a
  payload hash, origin-rooted, bounded `status`/`limit` query parameters).

A grant approved for one relay never authorizes a challenge, media token, or
HTTP token for any other destination.

## Browser integration

Install a release of `@openkey/sdk` that includes `OpenKeyNostr`, then use the
`nostr` client exposed by `OpenKey`:

```ts
import { OpenKey } from '@openkey/sdk';

const openkey = new OpenKey({ host: 'https://openkey.so' });

// Request the full working set in one consent card:
const identity = await openkey.nostr.connect({
  relayUrl: 'wss://relay.example',
  kinds: [0, 7, 9, 40002, 1984, 22242, 24242, 27235, 20001, 30300, 41010,
          9030, 9031, 9032, 9040, 9041, 9042, 9043, 9044],
  operations: ['nip44_encrypt', 'nip44_decrypt', 'nip59_wrap', 'nip59_unwrap'],
});

const event = await openkey.nostr.signEvent(identity.keyId, {
  pubkey: identity.pubkey,
  created_at: Math.floor(Date.now() / 1000),
  kind: 40002,
  tags: [['h', 'channel-id']],
  content: 'Hello from OpenKey',
});

// Named crypto operations - the secret key and conversation keys never leave custody:
const ciphertext = await openkey.nostr.nip44Encrypt(identity.keyId, {
  peerPubkey: identity.pubkey, // encrypt-to-self only
  plaintext: JSON.stringify(reminder),
});
const plaintext = await openkey.nostr.nip44Decrypt(identity.keyId, {
  peerPubkey: agentPubkey,
  payload: observerFrame.content,
});
const wraps = await openkey.nostr.nip59Wrap(identity.keyId, {
  content: 'hello in private',
  recipients: [peerPubkey], // 1..8; self-wrap is emitted first automatically
});
const rumor = await openkey.nostr.nip59Unwrap(identity.keyId, incomingWrap);
```

`connect()` returns only `keyId`, the hexadecimal public key, and `npub`. It
never returns a secret key or an OpenKey session token. The approval card
lists every requested capability with plain-language descriptions; sensitive
capabilities (moderation, membership, decryption) are labeled.

`signEvent()` is silent only while an unexpired, unrevoked grant covers the
exact client origin, key, event kind, and (for destination-bound kinds) the
event's own destination. Otherwise OpenKey shows its own origin-bound
approval iframe. For kinds `24242`/`27235` pass `opts.relayUrl` as a consent
hint so a first-use approval can bind the grant to the right relay; the hint
never widens what is signed.

The crypto operations follow the same pattern: silent under a grant naming
the operation, an approval card otherwise, and structured failures
(`interaction_required`, validation reason codes) with no sensitive data.

Applications must independently verify returned event IDs, public keys,
template fields, and Schnorr signatures before publishing.

## Signing boundary

Shared bounds for all kinds:

- timestamps within 120 seconds of the API clock;
- content up to 4,096 characters (8,192 for kind `30300`, whose content is a
  NIP-44 ciphertext);
- at most 20 tags, each containing 1-20 string values up to 512 characters.

Per-kind validators then enforce the exact Buzz payload shapes (tag order and
cardinality, hex/UUID/URL/enum syntax, duplicate-tag rejection, NIP-44
payload shape for kind `30300`, near-future expirations for kind `24242`,
method-bound payload-hash presence for kind `27235`). Malformed templates,
unsupported kinds, stale timestamps, origin mismatches, destination
mismatches, and `pubkey` mismatches fail before signing, with structured
reason codes.

Crypto-operation bounds: NIP-44 plaintexts 1-4,096 characters (encrypt is
strictly encrypt-to-self), ciphertext payloads bounded by the NIP-44 spec
maximum and validated structurally before any key derivation; NIP-59 wraps
carry 1-8 distinct recipients (never the sender), rumor timestamps within the
signing window, and unwrap verifies the wrap signature, recipient binding,
seal structure and signature, seal/rumor sender consistency, and the
recomputed rumor id before releasing only the bounded rumor. Seal and wrap
timestamps are randomized up to two days into the past inside the custody
boundary, per NIP-59.

## Custody and grants

- The database has a unique constraint on the user ID, and identity creation
  uses an atomic upsert. Concurrent first connections resolve to the same key.
- Secret key material is sealed with a TEE-derived key; unsealed secrets,
  conversation keys, and ephemeral wrap keys are zeroed after each operation.
  No route returns key material or a reusable conversation key.
- Grants are scoped to the canonical HTTP(S) client origin, enumerate kinds
  and operations explicitly, and can be revoked. Every result-producing route
  re-checks revocation and expiry immediately before releasing its result.
- Widget requests carry a random request ID and protocol version (still `1`;
  the new message types are additive). Messages are accepted only from the
  exact configured OpenKey origin and iframe window.
- Decisions are audited for signing and crypto operations with bounded,
  non-secret metadata: never plaintext, ciphertext bodies, secret keys, or
  sealed blobs.

## Rollout checklist

1. Apply the Prisma migrations (including
   `20260806090000_add_nostr_grant_operations`) before starting the API
   version that serves the Nostr routes.
2. Deploy API and web artifacts from the same reviewed commit.
3. Publish the SDK changeset, then pin consumers to that released version (or
   to a reviewed immutable source commit during coordinated pre-release CI).
4. Configure the public API/web origins and allow the OpenKey origin in the
   integrating application's `frame-src` CSP.
5. Run the real-browser connect, first-consent sign, silent sign, NIP-42,
   Blossom/NIP-98 destination-binding, NIP-44 round-trip, NIP-59 DM,
   restart, and revocation smoke tests against the production-like
   deployment.
6. Verify TEE attestation, database backups, monitoring, alerting, and
   rollback procedures before enabling users.

The capability model is versioned deliberately: expanding the kind allowlist,
adding operations, or changing grant semantics is a security-boundary change
and requires a separate review, a version bump in
`packages/tee/src/nostr-capabilities.ts`, and matching updates to the
capability matrix test.
