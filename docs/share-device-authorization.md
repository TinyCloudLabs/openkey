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

On any `/delegate` link, a `permissions` parameter that is present but not a
readable, non-empty UTF-8 JSON list (including `?permissions=` and a bare
`?permissions`) refuses the request; the default abilities apply only when the
parameter is absent. Paste codes are standard base64 of UTF-8 JSON.

The API enforces device constraints for requests that name a device
transaction. `/delegate` sends `deviceTransactionId` to
`/api/delegate/prepare`, `/api/delegate`, and `/api/delegate/complete`; when
that field is present, those three routes refuse the request before signing
and before the delegation header is sent to any host unless:

- the transaction is pending (unknown, expired, or already approved ids get
  `expired_token`);
- the Node origin is the transaction's;
- the session key is the transaction's. It is read from `jwk`, which must
  contain only `kty`, `crv`, `x`, and optionally `kid`; `kid`, when present,
  must be a non-empty string. Private, unknown, or `null`-valued fields, any
  other `kid` value, and padded coordinates are refused. For sign and
  `/complete` it is also read from the SIWE being signed (for `/complete`,
  the SIWE the wallet signed), and both must match;
- the expiry is no later than the requested TTL from now (5 s clock
  tolerance) and the transaction deadline plus the TTL. For sign and
  `/complete` the expiry comes from the signed SIWE; on `/prepare` it is the
  requested `expiry`.

The signed SIWE is read with the EIP-4361 grammar, not by searching for
`URI:` or `Expiration Time:` lines, and must be canonical: parsing and
re-serializing it must give back exactly the submitted bytes (LF line
endings, no extra or missing lines). Otherwise a decoy line in a separator
slot could disagree with what the positional parser behind the delegation
reads, so non-canonical messages are refused.

Refusals other than `expired_token` are `invalid_request`. Requests that
name no device transaction follow ordinary `/delegate` behaviour (see
"Ordinary `/delegate` links" below).
`/api/delegate/authorize-sign-prepare`, `/api/delegate/authorize-sign`,
`/api/delegate/authorize-sign-preview`, `/api/delegate/sign` (session and
manage-key OAuth callers), `/api/delegate/host`, and `/api/keys/:keyId/sign`
do not support device transactions: any request to them that carries
`deviceTransactionId` (whatever its value) is refused with 400
`device_transaction_unsupported`, and requests without it behave as before.

The default and maximum lifetime is 30 days, counted from approval.

## Ordinary `/delegate` links

A `/delegate` link without `deviceTransactionId` can be made by anyone, so
the page limits what it does with one:

- `callback` must be a loopback URL (`localhost`, `127.0.0.1`, or `[::1]`,
  as the TinyCloud CLI uses) or a registered app callback endpoint: an
  HTTPS origin plus exact path, with any query
  (`REGISTERED_CALLBACK_ENDPOINTS` in
  `apps/web/src/lib/delegate-link-policy.ts`, currently
  `https://mcp.tinycloud.xyz/connect/callback`, plus
  `VITE_DELEGATE_CALLBACK_URLS` for other deployments). Any other callback
  refuses the request before a key is prepared. The page POSTs with
  `redirect: 'error'`, so a redirect cannot forward the delegation. Without a
  callback the page shows a paste code and the caution "Only paste this code
  into a terminal you started yourself."
- `host` must be HTTPS, or HTTP on a loopback host. The consent screen shows
  the node, where the delegation is returned, and its expiry. A node that is
  neither a known TinyCloud node (`KNOWN_NODE_ORIGINS`: the bootstrap-trusted
  `https://node.tinycloud.xyz` and `https://tee.node.tinycloud.xyz`, plus
  `VITE_DELEGATE_NODE_ORIGINS`) nor on this device is flagged, and Approve
  refuses until the owner confirms they run or trust it.
- `/api/delegate/prepare` and `/api/delegate` cap the requested `expiry` at
  30 days; a longer request is clamped.

Wallet-key approvals on `/api/delegate/complete` bind the authorization
context to the address in the signed SIWE. A `prepared.address`, when
supplied, must equal it, and the signature must recover to that address
(`signature-mismatch` otherwise). Every check runs before the single-use
context is consumed and before host activation: the address and signature,
the signed SIWE expiry (`missing_expiration_time`), the context bindings
(user, key address, session key, host, space, immutable SIWE fields, request
baseline, and action selection; a `prepared.spaceId` whose string form is not
the bound space, `null` included, is refused here with `space-mismatch`), the
echoed session metadata, and the device-transaction window. On versioned
completions (an `authorizationContextToken` is present),
`prepared_metadata_mismatch` refuses a `prepared.verificationMethod` that is
not the signed SIWE's URI and a non-string `prepared.spaceId` whose string form
passes the binding check (for example the space wrapped in an array), which a
strict comparison after the binding check catches, and the session is built
from the signed SIWE and the bound context, never from the echoed `prepared`
block. A refused request leaves the
approval usable. The context is consumed by an atomic compare-and-delete just
before activation: of two concurrent completions one wins, and the other, like
any later replay, gets `context-not-found`. The managed approval on
`/api/delegate` refuses any echoed `prepared.spaceId` or
`prepared.verificationMethod` that disagrees with the bound context with
`prepared_metadata_mismatch`, builds its session from the bound context, and
consumes its context only after the signed-expiry and device-window checks,
just before signing. Token-less legacy `/complete` calls still pass the echoed
`prepared` block to the session setup. The reported `expirationTime`,
`expiresAt`, and `expiry` come from the signed SIWE, never from caller-supplied
fields.

## Request

`POST /api/device-authorizations` accepts `permissions` in the manifest shape
scoped CLI login uses: `{ service, space, path, actions }` with fully qualified
services and abilities. `reason` is optional (at most 200 characters after
whitespace normalization; control characters become spaces and bidirectional
overrides, every format (`\p{Cf}`) and default-ignorable
(`\p{Default_Ignorable_Code_Point}`) character, and the fillers U+00AD,
U+034F, U+061C, U+115F, U+1160, U+180E, U+3164, U+FFA0 and tag characters
U+E0000–U+E007F are removed; `/delegate` applies the same cleaning to any
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
