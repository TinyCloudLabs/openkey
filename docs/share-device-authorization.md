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
  callback the page offers a short lookup code with the full base64 delegation
  available as a fallback and cautions "Only paste this code into a terminal you
  started yourself." An unreachable callback uses the same fallback.

- `host` must be HTTPS, or HTTP on a loopback host. The consent screen shows
  the node, where the delegation is returned, and its expiry. A node that is
  neither a known TinyCloud node (`KNOWN_NODE_ORIGINS`: the bootstrap-trusted
  `https://node.tinycloud.xyz` and `https://tee.node.tinycloud.xyz`, plus
  `VITE_DELEGATE_NODE_ORIGINS`) nor on this device is flagged, and Approve
  refuses until the owner confirms they run or trust it.
- `/api/delegate/prepare` and `/api/delegate` cap the requested `expiry` at
  30 days; a longer request is clamped.

The ordinary manual handoff is separate from device authorization. After the
delegation is signed, the authenticated page posts the public delegation to
`POST /api/delegation-codes`; the response contains eight random base32
characters formatted `xxxx-xxxx`. `GET /api/delegation-codes/:code` is public
and returns that delegation for ten minutes (including repeat lookups), then
404. Expired rows are removed on subsequent publishes. Publishing requires a
session and accepts only expected delegation fields and public JWK parameters;
it does not store the CLI signing key. A broker failure leaves the full paste
code available on the page. This endpoint is not the
encrypted, one-time device relay described above.

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

After required-field validation, `/complete` rejects a non-string `signature`
with 400 before context consumption or host activation. Missing, `null`,
`false`, and `0` still receive the existing required-fields error; those
requests are also refused before either side effect. A successful external
wallet completion returns the same session proof as a managed approval:
`siwe` and the verified wallet `signature`, plus `address`, `chainId`,
`spaceId`, `delegationCid`, `delegationHeader`, and `verificationMethod`. This
lets the CLI perform its field gate and cryptographic proof verification
offline.

For the widget's `/api/delegate/authorize-sign-prepare` →
`/api/delegate/authorize-sign-preview` → `/api/delegate/authorize-sign`
flow, the final signing request checks the bound user, key, session JWK,
host, space, immutable SIWE fields, ReCap baseline and action selection;
it also checks narrowing, regenerated bytes, the preview approval's
selection and exact signed bytes, and any external-wallet signature.
A refusal consumes neither the authorization context nor its single-use
preview approval, so the same pending approval can be retried after
correction. Immediately before managed signing (or returning a verified
external signature), the route atomically compares and consumes both
tokens: a concurrent loser and a replay cannot sign. A managed signing
failure after consumption still requires a fresh approval.

An expired authorization context returns `context-expired` on
`/authorize-sign`, `/authorize-sign-preview`, the managed approval, and
versioned `/complete` only while its record remains stored. Issuing a new
context prunes expired records, after which the same token returns
`context-not-found`. An expired preview approval returns
`preview-approval-expired` on `/authorize-sign` until a new preview approval
prunes it, after which it returns `preview-approval-not-found`. In practice
an expired preview approval implies an expired context, which is reported
first. An empty final selection with required actions still returns
`required-action-missing`; unknown action IDs still return
`action-not-in-baseline`. When the caller has keys, `/authorize-sign` now
rejects another account's context with `400 user_mismatch`, as
`/authorize-sign-preview` already does, before inspecting the selection or
spending the owner's context. Previously, unrelated keys yielded
`404 key_not_found`; a case-variant record for the same wallet yielded
`400 user-mismatch` and spent the owner's context. A caller with no keys
still receives `404 key_not_found`.

## Prepared-SIWE CLI handoff (transport v2)

Replica-enabled OpenKey sign-in uses
`https://openkey.so/delegate#tv2=<unpadded base64url UTF-8 JSON>`. The CLI
must have an explicit `--owner` or independently verified stored EIP-155
owner identity before the Node SDK prepares the SIWE. An unknown owner
cannot use v2; it never falls back to the legacy delegation flow. The CLI
places the SDK's **exact** SIWE bytes and **public-only** Ed25519 JWK in:

```json
{
  "transportVersion": 2,
  "request": {
    "protocolVersion": 1,
    "siwe": "<exact SDK-prepared SIWE>",
    "jwk": {"kty": "OKP", "crv": "Ed25519", "x": "<public coordinate>"},
    "host": "https://node.example",
    "sessionDid": "<display-only CLI session DID>",
    "keyId": "<optional OpenKey signing key ID>"
  },
  "delivery": {
    "handoffId": "<CLI-generated 32-byte base64url ID>",
    "callback": "http://127.0.0.1:42317/callback/<22 base64url characters>",
    "state": "<independent 32-byte base64url value>",
    "cancelSecret": "<different 32-byte base64url value>"
  }
}
```

`presentation` may also be supplied in `request`; `callback` is optional
for paste-only use. The CLI rejects a canonical full URL over 8192 UTF-8
bytes with an explicit error, never a v1 fallback. The page applies the
same limit without counting its internal navigation marker. The API claim
body limit is 6 KiB. The fragment is not sent in HTTP requests or access
logs, but trusted same-origin page JavaScript can read it, including
`cancelSecret`.

The document bootstrap removes the fragment immediately. Client-side
navigation and hash changes scrub it and reload before legacy approval
can run. A pending request survives sign-in only in tab-scoped
`sessionStorage`, resumed by bare `/delegate` or the email sign-in's
internal `?transportVersion=2` return marker. An explicit v1 URL clears
stale v2 tab data; a new v2 fragment replaces the old one. A storage
write failure attempts to clear stale data and shows a nonresumable error,
never the old request. A document-level timer checks expiry on every
page load and clears the pending payload after five minutes even while
the user remains on the sign-in page. Data is also removed on claim,
cancellation or error; never use `localStorage`. After a claim, a refresh
cannot recover the request or signed result: the page asks for a new CLI
sign-in. No request or private JWK is put in a query string.

A session refresh in the original signed-out tab does not automatically
claim before the sign-in redirect: the user explicitly continues there,
or the authenticated return starts the claim in the new page. This avoids
consuming the one-use handoff just before a full-page navigation.

There is **no anonymous handoff creation** and no ticket resolve route.
Only after OpenKey authentication does the page send
`POST /api/delegate/handoffs/claim` with the decoded JSON above. It returns
`{transportVersion:2,ticket:<handoffId>,expiresAt:<ISO>}`. The server
validates canonical SIWE, public JWK and URI binding, exact host origin,
optional key ID, callback, and independent delivery values. The SIWE
`Issued At` must be no more than five minutes old (with 30 seconds of
future clock tolerance); an expired SIWE is refused. The account owns
the record at creation. A unique account/SIWE-nonce key prevents a
second signing handoff, while database-serialized admission permits at
most five new claims per authenticated account per five minutes. The
approval request expires no later than five minutes after claim or the
SIWE grant expiry, whichever is earlier. The user sees the **approval
request expiry** and the **signed grant expiry** as separate clocks.

The page shows the CLI session DID (display only), exact node host origin,
requested spaces and abilities, original SIWE, and the warning "Only
approve if you started this sign-in yourself on your own computer." The
selected OpenKey key must match a requested `keyId`; otherwise the user
chooses among account keys matching the SIWE address. The selected ID is
echoed for audit, not cryptographic proof. Authorize-sign
prepare/preview/sign bind the claimed handoff ID, key, public JWK, host
and original SIWE to a single context. The page displays the preview's
exact `signedMessage` before confirmation. Full selection signs the
original bytes; narrowing changes only a permitted ReCap subset. There
is no raw key mint or postapproval re-prepare.

Signing atomically consumes the claim even if browser delivery fails.
Only the successful signing response includes `deliveryState` and
`selectedKeyId`. The page constructs
`{transportVersion:2,state:deliveryState,selectedKeyId,result}`, where
`result` has exactly `protocolVersion`, `address`, `signature`,
`signedMessage`, `selectedActionKeys`, and `permissions`. The browser
POSTs it to the registered randomized loopback callback, with redirects
disabled; callback success requires the CLI's `{ "accepted": true }`
receipt after SDK verification and durable session/profile commit.
Otherwise the page offers the **same in-memory result** as a one-line
unpadded base64url UTF-8 paste code. No endpoint retrieves a signed
result by handoff ID.

The callback must be exactly `http://127.0.0.1` or `http://[::1]`,
port 1024–65535, path `/callback/<22 base64url characters>`, with no
query, fragment or userinfo. After claim, the CLI can cancel via
`POST /api/delegate/handoffs/cancel` with
`{ticket:<handoffId>,cancelSecret}`; the authenticated page can use
`/cancel-claimed` with `{ticket}`. Before claim, no server record exists
to cancel. On CLI cancellation or timeout the CLI must immediately
destroy the new candidate private JWK and callback state, preserving
any previous profile key. A later approval of that old fragment has no
held key and cannot pass the CLI state check. Wallet refusal before a
finalize request leaves page cancellation available; after finalize
might have succeeded, the page does not re-sign or retrieve a result.

### Owner revocation handoff

The same `#tv2` delivery envelope accepts an `owner-revocation` request with
exactly `kind`, `ownerDid`, `cid`, `nonce`, and `expiresAt`. The CLI supplies a
fresh nonce and an RFC3339 expiry. OpenKey validates the CID, nonce, owner DID,
and request fields; an expired request is refused. At claim time, the expiry
is capped at ten minutes. The confirmation screen shows the owner address,
short CID, effective expiry, and "This cannot be undone."

`POST /api/delegate/owner-revocation/prepare` binds the selected signing key
to the signed-in owner address and chain. OpenKey constructs the SIWE with
the page host, `ucan:<cid>` URI, supplied nonce, actual issuance time, and
the capped expiry. There is no statement, Not Before, or ReCap. The screen
says "Revoke this permission" and signs those exact bytes with the owner's
key through `/api/delegate/owner-revocation/sign`.

The callback and paste code carry the same one-use completion envelope:
`{transportVersion:2,state:<original state>,result:{siwe,signature}}`.
The `siwe` field is the exact signed text; `signature` is its EIP-191 hex
signature. The handoff's existing cancellation, timeout, and callback
acknowledgement rules apply.

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
