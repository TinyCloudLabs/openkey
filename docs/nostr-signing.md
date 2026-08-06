# Managed Nostr signing

OpenKey can hold one Nostr identity per user and sign a narrowly bounded set of
NIP-01 events without exposing the secret key to the integrating application.
The Nostr path uses BIP-340 Schnorr signatures and is separate from OpenKey's
Ethereum/ECDSA keys and signing routes.

## Browser integration

Install a release of `@openkey/sdk` that includes `OpenKeyNostr`, then use the
`nostr` client exposed by `OpenKey`:

```ts
import { OpenKey } from '@openkey/sdk';

const openkey = new OpenKey({ host: 'https://openkey.so' });
const identity = await openkey.nostr.connect({
  relayUrl: 'wss://relay.example',
});

const event = await openkey.nostr.signEvent(identity.keyId, {
  pubkey: identity.pubkey,
  created_at: Math.floor(Date.now() / 1000),
  kind: 9,
  tags: [['h', 'channel-id']],
  content: 'Hello from OpenKey',
});
```

`connect()` returns only `keyId`, the hexadecimal public key, and `npub`. It
never returns a secret key or an OpenKey session token. Supplying `relayUrl`
also requests consent for NIP-42 authentication events for that exact relay.

`signEvent()` is silent only while an unexpired, unrevoked grant covers the
exact client origin, key, event kind, and (for kind `22242`) relay. Otherwise
OpenKey shows its own origin-bound approval iframe.

Applications must independently verify the returned event ID, public key,
template fields, and Schnorr signature before publishing it.

## Signing boundary

The API accepts only:

- kind `9` channel messages;
- kind `22242` NIP-42 authentication events with exactly one `relay` tag and
  one `challenge` tag, and a relay matching the grant;
- timestamps within 120 seconds of the API clock;
- content up to 4,096 characters;
- at most 20 tags, each containing 1-20 string values;
- tag values up to 512 characters.

Malformed arrays, non-string tag members, unsupported kinds, stale timestamps,
origin mismatches, and events whose `pubkey` differs from the stored identity
fail before signing.

## Custody and grants

- The database has a unique constraint on the user ID, and identity creation
  uses an atomic upsert. Concurrent first connections resolve to the same key.
- Secret key material is sealed with a TEE-derived key and is zeroed after use.
- Grants are scoped to the canonical HTTP(S) client origin and can be revoked.
- Widget requests carry a random request ID and protocol version. Messages are
  accepted only from the exact configured OpenKey origin and iframe window.
- Signing decisions are audited without storing secret keys or sealed blobs.

## Rollout checklist

1. Apply the Prisma migrations before starting the API version that serves the
   Nostr routes.
2. Deploy API and web artifacts from the same reviewed commit.
3. Publish the SDK changeset, then pin consumers to that released version (or
   to a reviewed immutable source commit during coordinated pre-release CI).
4. Configure the public API/web origins and allow the OpenKey origin in the
   integrating application's `frame-src` CSP.
5. Run the real-browser connect, first-consent sign, silent sign, NIP-42,
   restart, and revocation smoke tests against the production-like deployment.
6. Verify TEE attestation, database backups, monitoring, alerting, and rollback
   procedures before enabling users.

The initial implementation intentionally supports only kinds `9` and `22242`.
Expanding the allowlist or grant semantics is a security-boundary change and
requires a separate review.
