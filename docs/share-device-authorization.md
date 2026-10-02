# Device authorization

OpenKey owns the transaction state for CLI login from a remote or headless
machine. The unauthenticated CLI creates a local Ed25519 session key, a 256-bit
device secret, an independent PKCE verifier, and an ephemeral P-256 relay key.
It sends only the public session and relay bindings, hashed secret, PKCE
challenge, requested permissions, an optional reason, Node/Share origins, and
requested expiry.

OpenKey returns a ten-minute transaction, generic verification URL, and short
user code. `/device` lists every requested capability, the reason, both
origins, and a warning to approve only a request the person started on their
own device, and offers lifetimes up to the requested one. The user then signs
in with the existing OpenKey/passkey flow and reviews the request on
`/delegate`, where each optional capability can be unchecked.

`/delegate` enforces the device consent rules itself, so a hand-made
`/delegate?…&deviceTransactionId=…` link gets no further than one that went
through `/device`:

- it looks the request up by its user code (`deviceUserCode`) before any key
  is prepared, and refuses the link unless the transaction id, session DID,
  session and relay keys, Node and Share origins, and permissions all equal
  the server's pending request, and the link's `expiry` is within the
  requested lifetime;
- the reason shown and signed is the server-cleaned reason, never the link's;
- Approve refuses until the owner ticks "I started this request myself, on a
  device I control" next to the same-device warning.

The API enforces the lifetime as well. `/delegate` sends `deviceTransactionId`
to `/api/delegate/prepare`, `/api/delegate`, and `/api/delegate/complete`;
those routes then refuse (`invalid_request`, or `expired_token` once the
transaction is no longer pending) a delegation whose session key or Node
origin differs from the pending request, or whose expiry is later than the
requested TTL from now (5 s clock tolerance) or the transaction deadline plus
the TTL. The check runs before signing and before the delegation header is
sent to any host, so an overlong delegation is never created or activated.

The default and maximum lifetime is 30 days, counted from approval.

## Request

`POST /api/device-authorizations` accepts `permissions` in the manifest shape
scoped CLI login uses: `{ service, space, path, actions }` with fully qualified
services and abilities. `reason` is optional (at most 200 characters after
whitespace normalization; control characters become spaces and bidirectional
overrides and invisible or filler characters (U+00AD, U+034F, U+061C,
U+115F, U+1160, U+180E, U+200B–U+200F, U+202A–U+202E, U+2060–U+2064,
U+2066–U+2069, U+3164, U+FEFF, U+FFA0, and the tag characters
U+E0000–U+E007F) are removed; `/delegate` applies the same cleaning to any
reason it shows).
`delegationTtlSeconds` must be between 60 seconds and 30 days. The
approved delegation may expire at most `delegationTtlSeconds` after approval,
and approval must happen before the ten-minute transaction deadline.

The legacy request, exactly `tinycloud.capabilities/read` on `applications`
with an empty path, is still accepted and normalized as before.

## Device-flow scope policy

Anyone can start a device request and send its code to someone else, so the
device flow accepts a narrower set of capabilities than browser login.
Anything outside this policy is rejected with `invalid_scope`:

- one space per request, given as a space name or a `tinycloud:pkh` space URI;
  the `account` (account registry), `applications` (application registry), and
  `secrets` spaces are rejected, except for the legacy request above;
- services are limited to `tinycloud.kv` and `tinycloud.capabilities`;
- abilities are limited to KV `get`/`list`/`metadata`/`put`/`del` and
  capabilities `read`. SQL, delegation, space, hooks, encryption, secrets,
  DuckDB, VFS, and wildcard abilities are rejected;
- KV grants name an explicit relative path: no whole-space grants, no
  wildcards, empty or `.`/`..` segments, and no `secrets/` or `vault/` roots.
  Capabilities grants use the empty path;
- no KV path may cover another of the same request. Node path coverage is a
  segment prefix, so `shares` and `shares/`, or `a` and `a/b`, cannot both be
  requested: unchecking the narrower one would not remove that access;
- `tinycloud.capabilities/read` with path `""` in the requested space is
  required. Every OpenKey delegation carries it, so the consent page shows it
  as required rather than optional, and requests without it are rejected
  instead of having it added silently;
- at most 16 entries; repeated service/path pairs and repeated abilities are
  rejected; entries carry no other fields.

`tinycloud.sql` is deferred. The current Node authorizes SQL grants for
descendant paths but selects the database by the final path segment, so a
grant for `notes` could address `notes/private` and open database `private`.
Native publishing needs KV only; SQL can return once Node binds the database
to the granted path.

### Space identity

Wherever device-flow spaces are compared (one space per request, approval
binding against the request, signed grants against the request, and the
single-space check when `/delegate/prepare` signs), a
`tinycloud:pkh:eip155:<chain>:<address>:<name>` URI is compared with the
Ethereum address case-insensitively; the chain and space name are exact. The
signed ReCap carries the EIP-55 address, so a request spelled with a lowercase
address still matches. A bare space name matches the signer's space of that
name and never equals a full URI within one request. Bindings are always
stated in the request's own spelling.

## Approval binding

The owner may uncheck optional capabilities, so the approved set is a subset
of the request that keeps `tinycloud.capabilities/read`. The browser derives it
from the signed delegation's grants and
states it in the request's manifest form, in request order. The approval
`binding.permissions` and the relayed delegation's `permissions` are that same
list. The API rejects a binding that is not such a subset (`invalid_result`),
and the CLI's poll returns it as `binding.permissions`.

The requested scope, reason, requested lifetime, and approved subset are
stored together in the existing `permissions` JSON column, so this needs no
migration. Rows written before TC-539 hold a bare permission array and are
still read; their lifetime is derived from the stored deadline and capped at
30 days.

## Deployment and rollback

Ship the web first, then the API. TC-539 is split so the web change
(`feat/tc-539-web`) can go live alone: it works against the old API, and
legacy Share-only requests keep working. Only then deploy the API change.
The reverse order is unsafe: the old `/device` and `/delegate` would present a
KV request from the new API as a Share request, without the TC-539 consent
protections.

The new web tolerates the old API: when the lookup has no
`delegationTtlSeconds`, it derives the lifetime from
`delegationExpiresAt − transactionExpiresAt` (capped at 30 days) instead of
failing.

Roll the API back whenever the web is rolled back (the old web must not face
the new API, above), and roll both back together:

- An API rolled back to `495b9d3` cannot parse rows this version wrote
  (`permissions` stored as `{ version: 2, requested, … }`); its lookup returns
  that object as-is. Transactions in flight (at most ten minutes old) fail,
  and their CLIs must restart the device login.
- Worse, the old web reads such a lookup as `requestedPermissions = []`, so
  for an in-flight transaction it prepares, signs, and activates the default
  abilities with the host before the old API refuses the binding. Before
  rolling back, stop new device starts and close pending rows, for example
  `UPDATE device_authorization SET status = 'DENIED' WHERE status = 'PENDING';`,
  or wait out the ten-minute transaction window.

## Security invariants

- `sessionDid` is derived from and compared with the supplied public Ed25519
  JWK; private JWK fields are rejected.
- Requests must satisfy the device-flow scope policy above.
- Node origin, Share origin, approved permissions, session key, and approved
  expiry are checked again when approval is relayed and when the CLI consumes
  it.
- Device secrets and PKCE verifiers are independently high entropy. Only their
  SHA-256 digests are stored.
- Creation and polling are rate-limited. Transactions expire after ten minutes.
- The browser derives an ECDH/HKDF key from the CLI relay public key and
  encrypts the approved delegation with AES-256-GCM before sending it to the
  device API. The relay stores only that opaque envelope and consumes it once
  with an atomic status transition; neither the relay nor its rows receive a
  plaintext delegation or CLI private key.
- Share object retention remains seven days.

The production database change is
`20260814_0001_share_device_authorization`. `DEVICE_AUTH_ENCRYPTION_SECRET`
may provide a dedicated secret for privacy-preserving request-IP rate-limit
hashes; otherwise OpenKey uses `BETTER_AUTH_SECRET`. Production refuses to
start the device route without one of those secrets.

## Legacy Share smoke

`scripts/share-device-auth-smoke.ts` covers the legacy one-shot Share upload
request only; it is not the acceptance test for native publishing with a
manifest. After building `@tinycloud/cli`, run:

```bash
bun scripts/share-device-auth-smoke.ts --cli /absolute/path/to/js-sdk/packages/cli/dist/index.js
```

This starts real local device, Node-attestation, and registry HTTP boundaries,
invokes the public CLI command, and verifies end-to-end relay encryption,
device prompting, cryptographic delegation persistence, one-shot-attested
uploads, seven-day retention, and the complete Share URL. It does not automate
the separate human passkey/browser approval journey.

Native publishing acceptance uses the CLI's built-in manifest
(`xyz.tinycloud.share/shares/`: `put`, `get`; `shares/`: `put`, `get`,
`metadata`, `list`; `""`: `tinycloud.capabilities/read`) and is approved
through `openkey.so/device` by a throwaway account.
