# Native TinyCloud delegation

This is the protocol contract that lets a public native OAuth client get a
TinyCloud session delegation from OpenKey (TC-773; TC-520 option 2). The app
holds an Ed25519 session key on the device. After the user approves in the
system browser, OpenKey signs a capability-limited SIWE with the user's
canonical key, delegating to that session key. A refresh token, used together
with a proof from the same session key, renews the delegation within the
approved capabilities. It can never get a new signature for anything else or
widen the grant.

This document is normative for the OpenKey API (O2–O5), the client SDKs
(TC-774) and Exo (TC-775). SQL capabilities also depend on the tinycloud-node
isolation fix (TC-780; see [TinyCloud node dependency](#tinycloud-node-dependency-tc-780)).

Conventions:

- `b64url` is unpadded base64url (RFC 4648 §5).
- Times in JSON bodies are ISO-8601 UTC strings; JWT claims are Unix seconds.
- Every error body is `{"error": "<code>", "error_description"?: "<text>"}`.
  Clients branch on `error`, never on `error_description`.

## Flow

1. The app reads the discovery metadata and generates an Ed25519 session key,
   a PKCE verifier and a `state` value.
2. **PAR:** the app posts the authorization parameters, including the session
   public key and the requested permissions, and gets a `request_uri`.
3. **Authorize:** the app opens the authorization endpoint with `client_id`
   and `request_uri` in ASWebAuthenticationSession (iOS) or a Custom Tab
   (Android).
4. The user signs in to OpenKey (passkey, email OTP or social login).
5. **Consent:** the consent page prepares an immutable preview, the user
   approves or denies it, and OpenKey signs only after approval.
6. **Callback:** the browser returns `code`, `state` and `iss` to the
   registered redirect URI, or `error=access_denied`.
7. **Code exchange:** the app redeems the code with the PKCE verifier and an
   `OpenKey-Session-Proof`. The response contains the OAuth tokens and
   `tinycloud_delegation`.
8. **Renew** before the delegation expires; **revoke** at sign-out. Both
   require a session proof.

PAR is a design choice: the alternative was putting these parameters on the
authorization URL. RAR (RFC 9396) is used only to encode the request.

## Discovery and issuer

The issuer is `https://api.openkey.so/api/auth`, not the server origin. Clients
are configured with `{issuer, clientId, redirectUri}` and fetch RFC 8414
metadata using path insertion:

```text
GET https://api.openkey.so/.well-known/oauth-authorization-server/api/auth
```

The relevant fields, as published in production:

```json
{
  "issuer": "https://api.openkey.so/api/auth",
  "authorization_endpoint": "https://api.openkey.so/api/auth/oauth2/authorize",
  "token_endpoint": "https://api.openkey.so/api/auth/oauth2/token",
  "pushed_authorization_request_endpoint": "https://api.openkey.so/api/auth/oauth2/par",
  "tinycloud_delegation_renew_endpoint": "https://api.openkey.so/api/auth/oauth2/tinycloud/renew",
  "tinycloud_delegation_revocation_endpoint": "https://api.openkey.so/api/auth/oauth2/tinycloud/revoke",
  "code_challenge_methods_supported": ["S256"],
  "authorization_response_iss_parameter_supported": true
}
```

The last three endpoint fields are OpenKey extensions that the API adds to the
provider metadata. The client must refuse the metadata unless:

- `issuer` is byte-for-byte equal to the configured issuer;
- every URL uses HTTPS;
- every endpoint is on the issuer's origin.

The client uses the discovered URLs as they are. It does not build them from
the issuer. Each session proof's `htu` is the exact discovered URL of the
endpoint it is sent to. OpenKey compares it with the URL built from
`BETTER_AUTH_URL` + `/api/auth` + the endpoint path.

## Client enablement and ceiling

### Who can request a delegation

`tinycloud:delegation` is a restricted scope. It is **never** in any default
scope set: not in `DEFAULT_OAUTH_SCOPES`, `PUBLIC_CLIENT_SCOPES`,
`DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES`, or the tenant console's fixed
list. `RESTRICTED_SCOPES` (`tinycloud:session`, `tinycloud:manage-key`,
`tinycloud:delegation`) is subtracted from every derived default.

A client becomes able to request a delegation only when an OpenKey admin
**enables** it. Enabling writes `OauthClient.tinycloudNativeDelegation` and
adds `tinycloud:delegation` to the client's scopes in the same write. One
shared validator (`services/native-delegation/policy.ts`) serves both
enablement paths:

- the admin route;
- `scripts/ci-register-oauth-client.ts`, run by the
  `register-oauth-client.yml` workflow. This is the production path, because
  `ADMIN_API_KEY` exists only inside the CVM.

Enablement is refused unless the client is `type: "native"`, public, uses
`token_endpoint_auth_method: "none"`, and is not disabled. An admin PATCH that
adds or removes `tinycloud:delegation` on its own is refused. Dynamic client
registration and console-registered SPAs cannot get the scope.

Further scope isolation:

- The authorize guard refuses `tinycloud:delegation` unless the request
  either carries a `request_uri` or carries a `tinycloud_request` that passes
  the server-side [binding check](#tinycloud_request-binding). The query
  parameter alone is never trusted. For a delegation-enabled client, the
  guard also refuses an authorize request that omits `scope` and has no
  `request_uri`, because the provider would otherwise fall back to all of
  the client's scopes.
- An access token issued with `tinycloud:delegation` grants no signing.
  `/api/delegate/sign` returns 403 for it, and stays limited to confidential
  `web` clients.
- An ordinary SPA sign-in is unchanged.

### Ceiling

`OauthClient.tinycloudNativeDelegation` is the client's ceiling. Only admins
can set it, and the request can never exceed it.

```json
{
  "version": 1,
  "appId": "xyz.tinycloud.tinychat",
  "tinycloudHost": "https://tee.node.tinycloud.xyz",
  "kv": {
    "paths": ["xyz.tinycloud.tinychat/threads/", "xyz.tinycloud.tinychat/connectors/"],
    "actions": ["get", "put", "list", "del", "metadata"]
  },
  "sql": {
    "databases": [
      "xyz.tinycloud.tinychat/threads",
      "xyz.tinycloud.tinychat/canvas",
      "xyz.tinycloud.tinychat/connectors"
    ],
    "actions": ["read", "write", "schema"]
  },
  "maxDelegationTtlSeconds": 3600,
  "grantLifetimeSeconds": 2592000,
  "siweDomain": "openkey.so"
}
```

| Field | Rule |
|---|---|
| `version` | `1`. |
| `appId` | Reverse-DNS style. `[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]`, at most 128 characters. Every path is confined to `<appId>/`. |
| `tinycloudHost` | Must be in `TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS` (`tinycloud-bootstrap.ts`). This is the only node the delegation is activated on and the only host a hosting signature can name. Requests cannot supply a host. |
| `kv.paths` | Paths under `<appId>/`, using the device-flow path grammar (`[A-Za-z0-9._~@+=,:-]` segments; no `.` or `..` segments; `secrets` and `vault` roots refused). A trailing `/` makes it a prefix grant. |
| `kv.actions` | A subset of `get`, `put`, `list`, `del`, `metadata`, meaning `tinycloud.kv/<action>`. |
| `sql` | `null`, or an object. Accepted only if `tinycloudHost` is in `TINYCLOUD_SQL_ISOLATED_HOSTS` (server env). This is checked at enablement, at PAR and at every renewal, and fails closed. |
| `sql.databases` | Exact database identities `<appId>/<name>`, with exactly one segment after the `appId` and no trailing `/`. |
| `sql.actions` | A subset of `read`, `write`, `schema`, meaning `tinycloud.sql/<action>`. |
| `maxDelegationTtlSeconds` | 300–86400, default 3600. The lifetime of each signed delegation. |
| `grantLifetimeSeconds` | 300–2592000, default 2592000 (30 days). The absolute lifetime of a grant, after which a browser sign-in is required. |
| `siweDomain` | Optional, default `openkey.so`. The SIWE `domain`. |

Exo's ceiling is the one above: the applications-space entries of its
manifest, without secrets or encryption.

## Permissions and the signed session SIWE

Requests and responses list permissions as manifest entries with
fully-qualified abilities:

```json
{ "service": "tinycloud.kv", "space": "applications", "path": "xyz.tinycloud.tinychat/threads/", "actions": ["tinycloud.kv/get", "tinycloud.kv/put"] }
```

- `space` is always `applications`; any other space is refused.
- `service` is `tinycloud.kv`, `tinycloud.sql` or `tinycloud.capabilities`.
- Every request includes
  `{"service":"tinycloud.capabilities","space":"applications","path":"","actions":["tinycloud.capabilities/read"]}`.
  The user cannot remove it.
- A KV entry's path must equal or lie under one of the ceiling's `kv.paths`,
  and its actions must be in `kv.actions`.
- A SQL entry's path must equal one of the ceiling's `sql.databases`, and its
  actions must be in `sql.actions`.
- No two entries for the same service may overlap.

OpenKey signs exactly one message: the **session SIWE** (EIP-4361 with an
EIP-5573 ReCap). The canonical key signs it with EIP-191. The bytes are built
by `prepareDelegationSession`, the same builder used for web sessions.

| Field | Value |
|---|---|
| `domain` | Ceiling `siweDomain`, default `openkey.so` |
| address | The user's canonical key address (`primaryKeyWhere`) |
| `URI` | The session `did:key` derived from the PAR `session_key` |
| `Version` / `Chain ID` | `1` / `1` |
| `Nonce` | The request's `siwe_nonce` if given, otherwise a random server nonce |
| `Issued At` / `Expiration Time` | The moment OpenKey signs / that moment + the delegation TTL ([TTL rules](#ttl-rules)). Prepare previews them with prepare-time values; approve sets them at signing ([Approve](#approve)). |
| `Resources` | One `urn:recap:` resource covering exactly the approved permissions in the user's `applications` space |

The only other signature in this flow is the optional, separately disclosed
hosting delegation ([Host plan](#host-plan)). There is no path to signing
arbitrary messages. Only Ed25519 session keys are supported, because the
TinyCloud session manager accepts no other type.

## Pushed authorization request

```text
POST /api/auth/oauth2/par
Content-Type: application/x-www-form-urlencoded
```

No cookies or credentials are sent. Fields:

| Field | Required | Value |
|---|---|---|
| `client_id` | yes | The delegation-enabled native client. |
| `response_type` | yes | `code` |
| `redirect_uri` | yes | Exactly equal to a registered redirect URI. |
| `state` | yes | Fresh and unguessable. |
| `code_challenge` | yes | `b64url(SHA-256(code_verifier))` |
| `code_challenge_method` | yes | `S256` |
| `scope` | yes | Space-separated. Must contain `tinycloud:delegation` and `offline_access`, and may add `openid`, `email` and `keys`. |
| `authorization_details` | yes | A JSON array holding exactly one `tinycloud_delegation` object (below), encoded as the field's string value. |

Every form key may appear at most once; a duplicated key fails the whole
request. Any other field, including any host field, is refused.

`authorization_details[0]`:

| Member | Required | Value |
|---|---|---|
| `type` | yes | `"tinycloud_delegation"` |
| `session_key` | yes | Public Ed25519 JWK: `{"kty":"OKP","crv":"Ed25519","x":"<b64url 32 bytes>"}`, optionally with a non-empty string `kid` (ignored by the [thumbprint](#session-key-thumbprint)). `x` must decode to exactly 32 bytes and re-encode to the same string. Private (`d`), `null`-valued or other members are refused. |
| `permissions` | yes | A non-empty array of permission entries ([Permissions](#permissions-and-the-signed-session-siwe)), all inside the ceiling. |
| `ttl_seconds` | no | 300 to the ceiling's `maxDelegationTtlSeconds`. Defaults to the ceiling value. |
| `siwe_nonce` | no | `[A-Za-z0-9]{8,64}`. Lets the app bind its own backend nonce into the SIWE. |

Any other member is refused. Example (shown on separate lines; on the wire it
is one form-encoded body):

```text
client_id=exo-native
response_type=code
redirect_uri=xyz.tinycloud.exo://openkey/callback
state=Xb2q…
code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method=S256
scope=openid offline_access tinycloud:delegation
authorization_details=[{"type":"tinycloud_delegation","session_key":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},"permissions":[{"service":"tinycloud.capabilities","space":"applications","path":"","actions":["tinycloud.capabilities/read"]},{"service":"tinycloud.kv","space":"applications","path":"xyz.tinycloud.tinychat/threads/","actions":["tinycloud.kv/get","tinycloud.kv/put","tinycloud.kv/list"]},{"service":"tinycloud.sql","space":"applications","path":"xyz.tinycloud.tinychat/threads","actions":["tinycloud.sql/read","tinycloud.sql/write"]}],"ttl_seconds":3600,"siwe_nonce":"n0nce4exo"}]
```

On success OpenKey stores a `PENDING` request holding the public JWK, its
thumbprint `sessionJkt` ([Session key thumbprint](#session-key-thumbprint)),
the session DID, the validated
permissions, the TTL, the nonce and the PKCE challenge. It responds:

```http
HTTP/1.1 201 Created
Cache-Control: no-store
Content-Type: application/json

{"request_uri":"urn:ietf:params:oauth:request_uri:<opaque id>","expires_in":90}
```

The request as a whole expires 10 minutes after PAR. PAR errors are
synchronous JSON:

| HTTP | `error` | Cause |
|---|---|---|
| 401 | `invalid_client` | Unknown or disabled client. |
| 400 | `unauthorized_client` | The client is not native, public and `none`-auth, or delegation isn't enabled for it. |
| 400 | `invalid_request` | Missing or duplicated field, an unknown field, a redirect URI mismatch, a non-S256 or malformed challenge. |
| 400 | `invalid_scope` | `tinycloud:delegation` or `offline_access` missing, or a scope the client doesn't have. |
| 400 | `invalid_authorization_details` | Not exactly one `tinycloud_delegation` object, an unknown member, an invalid JWK, permissions outside the ceiling, `space` other than `applications`, missing `tinycloud.capabilities/read`, an out-of-range TTL, a malformed nonce, or SQL requested when the host isn't SQL-isolated. |

## Authorization and callback

The app opens:

```text
GET {authorization_endpoint}?client_id=<client_id>&request_uri=<urlencoded request_uri>
```

The `requestUriResolver` loads the request, requires the same `client_id`,
status `PENDING`, and a `request_uri` no older than 90 seconds. It then marks
the request `RESOLVED`, so the URI is single-use. It returns the stored
parameters plus `prompt=consent` and `tinycloud_request=<id>`. `prompt=consent`
overrides the client's `skipConsent` and any saved provider consent, so the
consent screen always appears.

An unknown, expired or reused `request_uri` does not redirect to the app. The
provider redirects the browser to its own error page:

```text
https://api.openkey.so/api/auth/error?error=invalid_request_uri&error_description=request_uri+is+invalid+or+expired
```

That is the provider default (`${baseURL}/error`), because OpenKey sets no
`onAPIError.errorURL`, and this spec does not require one. The SDK reports a
sheet that closes without a callback as `USER_CANCELLED`.

If the user isn't signed in, OpenKey sends them to `/auth/login` and then
resumes with the stored, resolved query. Login and the consent page run on
`https://openkey.so`.

### `tinycloud_request` binding

The post-login re-entry is a plain `GET` to the authorize endpoint carrying
the resolved query. `tinycloud_request` therefore arrives as an ordinary query
parameter, and the provider does not check the query's `sig` or `exp` on a
`GET`. Anyone can put `tinycloud_request=<id>` on an authorize URL, so the
authorize guard checks it on the server, against stored values.

When there is no `request_uri` and the query carries `tinycloud_request=<id>`,
the guard loads request row `<id>`. The row must exist, have status
`RESOLVED`, and be unexpired. Only OpenKey's own `requestUriResolver` sets
`RESOLVED`, so a row that was never resolved (`PENDING`) or has moved past
`RESOLVED` is refused.

The guard then **rebuilds the authoritative query** from the row, exactly as
the resolver produced it:

```text
client_id=<row.clientId>
response_type=code
redirect_uri=<row.redirectUri>
state=<row.state>
scope=<row.scopes, space-separated, stored order>
code_challenge=<row.codeChallenge>
code_challenge_method=S256
prompt=consent
tinycloud_request=<row.id>
```

The incoming query must contain every one of these keys exactly once, with
exactly these values. The only other keys allowed are the provider's
signed-query envelope (`exp`, `ba_iat`, `ba_pl`, `sig`), which the guard
ignores and never trusts. A missing key (for example a replay without
`prompt=consent`), a changed value (for example a different `state`), a
duplicated key or any extra key is refused. The guard redirects to the same
error page with `error=invalid_request`, never to the app. An authorize
request that has `tinycloud:delegation` in its scope but neither a
`request_uri` nor a passing binding is refused the same way. Because
`prompt=consent` cannot be dropped, saved provider consent can never skip the
consent page for a native request.

The login page forwards only an allowlist of authorize parameters
(`OAUTH_AUTHORIZE_KEYS` in `apps/web/src/lib/auth-flow.ts`). That list must
include `tinycloud_request`; otherwise the post-login re-entry loses the
binding and is refused.

Callbacks to the registered redirect URI:

```text
xyz.tinycloud.exo://openkey/callback?code=<code>&state=<state>&iss=https%3A%2F%2Fapi.openkey.so%2Fapi%2Fauth
xyz.tinycloud.exo://openkey/callback?error=access_denied&state=<state>&iss=https%3A%2F%2Fapi.openkey.so%2Fapi%2Fauth
```

For every callback, including error callbacks, the client:

1. requires `iss` to equal the configured issuer (RFC 9207);
2. requires `state` to equal the value it sent (otherwise `STATE_MISMATCH`);
3. treats `error=access_denied` as a terminal, user-visible denial
   (`ACCESS_DENIED`). Any other `error` is a failed sign-in.

The authorization code is valid for 10 minutes.

## Consent: prepare, approve, deny

The consent page (`/oauth/consent` on `openkey.so`) reads `tinycloud_request`
from the provider's signed consent query and calls three routes. They
authenticate with the browser's OpenKey session cookie, accept only OpenKey
origins, and are not under the public CORS policy.

### Prepare

```text
POST /api/oauth/tinycloud/requests/:id/prepare
Content-Type: application/json

{}
```

Under the [lock order](#global-lock-order), OpenKey:

1. requires the request to be `RESOLVED` and unexpired;
2. binds `request.userId` to the session user on the first prepare, and
   returns 403 if a different user prepares it later;
3. resolves the user's canonical key;
4. builds a preview of the session SIWE. Its TTL is min(requested TTL,
   `maxDelegationTtlSeconds`, `grantLifetimeSeconds`) from the current
   ceiling, and its nonce is the request's `siwe_nonce`, or a server nonce
   generated on the first prepare and reused by later revisions. Its
   `Issued At` and `Expiration Time` hold prepare-time values that approval
   replaces ([Approve](#approve));
5. builds the [host plan](#host-plan) if one is needed;
6. inserts an immutable `TinyCloudNativePreparation` with the next
   `revision`, and sets `request.currentRevision` to it.

The digest is `b64url(SHA-256(JCS(preview)))`. `preview` is
`{requestId, revision, userId, keyId, address, sessionSiwe, permissions, hostPlan}`
and JCS is RFC 8785 canonical JSON. Each prepare creates a new revision; an
older revision is never changed.

```json
{
  "requestId": "<id>",
  "revision": 2,
  "digest": "<b64url SHA-256>",
  "client": {
    "clientId": "exo-native",
    "name": "Exo",
    "icon": "https://…/icon.png",
    "organization": "TinyCloud Labs",
    "verified": false
  },
  "redirectScheme": "xyz.tinycloud.exo",
  "address": "0x…",
  "keyId": "<canonical key id>",
  "sessionDid": "did:key:z6Mk…",
  "sessionSiwe": "<exact SIWE bytes to be signed>",
  "permissions": [ … ],
  "tinycloudHost": "https://tee.node.tinycloud.xyz",
  "ttlSeconds": 3600,
  "grantLifetimeSeconds": 2592000,
  "hostPlan": null
}
```

The page renders **only** this server data (`@openkey/capability-review` and
`SigningApproval`). It shows:

- the app's name and icon, its owning organization, and the label
  **Unverified app**;
- the return scheme;
- the node;
- every permission, as path and actions;
- the delegation lifetime, as a duration from approval ("1 hour"), never
  the preview's timestamps, and how long the app may keep renewing;
- the host plan, as its own item, when it is present.

### Approve

```text
POST /api/oauth/tinycloud/requests/:id/approve
Content-Type: application/json

{"revision":2,"digest":"<digest>","sessionSiwe":"<echoed bytes>","hostSiwe":"<echoed bytes>"}
```

`hostSiwe` is required if and only if `hostPlan` is non-null. Under the same
lock order, OpenKey requires:

- status `RESOLVED`;
- `now < request.expiresAt`, i.e. within 10 minutes of PAR;
- `userId` equal to the session user;
- `revision === currentRevision`;
- a digest equal to the stored one;
- echoed bytes identical to the stored `sessionSiwe` and `hostSiwe`;
- the same canonical key;
- the revision's TTL ≤ min(`maxDelegationTtlSeconds`,
  `grantLifetimeSeconds`) of the **current** ceiling. If the ceiling has
  shrunk since prepare, approve returns 409 `preparation_superseded` and the
  page prepares again.

It then records `request.consentGeneration` as the current
[consent generation](#consent-generation-and-withdrawal).

**Signing-time timestamps.** At signing time `t`, OpenKey rebuilds the session
SIWE with `prepareDelegationSession` from the approved revision's inputs
(address, chain ID, domain, session JWK, permissions and nonce), with
`Issued At = t` and `Expiration Time = t + ttlSeconds`. The rebuilt message
must match the approved `sessionSiwe` line for line, except for those two
lines. Otherwise approval fails with 409 `preparation_mismatch` and nothing is
signed. The canonical key signs the rebuilt bytes. OpenKey builds the
delegation from them (`completeSessionSetup`), stores it, sets `APPROVED` and
`approvedRevision`, and commits. **No canonical-key signature happens before
this point.**

The user therefore approves every signed field except the two timestamps, and
those are fixed relative to approval: their difference is the approved TTL. A
slow consent no longer eats into the delegation's lifetime. The host SIWE has
no expiry and is signed exactly as approved.

After the commit, OpenKey activates the delegation on `tinycloudHost`
([Host plan](#host-plan)) and responds:

```json
{"status":"APPROVED","revision":2,"hosting":"existing"}
```

The page then posts provider consent `{accept: true, oauth_query}` to
`/api/auth/oauth2/consent`. That issues the code, and the code's stored query
keeps `tinycloud_request`.

### Deny

```text
POST /api/oauth/tinycloud/requests/:id/deny
Content-Type: application/json

{}
```

Deny sets a `RESOLVED` request to `DENIED` and returns `{"status":"DENIED"}`.
The page then posts provider consent `{accept: false, oauth_query}`, which
redirects with `error=access_denied&state=…&iss=…`.

### Consent errors

| HTTP | `error` | Cause |
|---|---|---|
| 401 | `unauthorized` | No OpenKey session. |
| 403 | `request_user_mismatch` | The request is bound to a different user. |
| 404 | `request_not_found` | Unknown id. |
| 409 | `request_not_pending` | The status isn't `RESOLVED`, or `now ≥ request.expiresAt` (10 minutes after PAR). |
| 409 | `preparation_superseded` | `revision` isn't current (another tab prepared again, or the host plan was refreshed), or the ceiling shrank below the revision's TTL. Prepare again. |
| 409 | `preparation_mismatch` | Wrong digest, changed echoed bytes, changed canonical key, or a signing-time rebuild that differs from the approved SIWE in a line other than `Issued At` / `Expiration Time`. |
| 503 | `temporarily_unavailable` | Lock contention ([Global lock order](#global-lock-order)). |

All of these are refused before anything is signed.

## Host plan

A first-time user may not have an `applications` space on the client's node
yet. Creating it needs a second signature: a permanent hosting delegation for
that node. This signature is the only one OpenKey makes beyond the session
SIWE, and it is limited as follows:

- **Host:** always the ceiling's `tinycloudHost`, which must be in
  `TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS`. Neither the app nor the request can
  name a host.
- **When planned:** at prepare, unless `TinyCloudBootstrapState` already
  records completion for this key and host.
- **Contents:** `{host, spaceId, peerId, hostSiwe}`, where
  `peerId = fetchPeerId(host, spaceId)` and `hostSiwe` comes from
  `generateHostSIWEMessage`. The plan is included in the preparation digest,
  and approval echoes `hostSiwe`.
- **Disclosure:** the consent page shows the plan as a separate item:
  "If your `applications` space doesn't exist on `<node>` yet, OpenKey will
  also create it there. This is a permanent hosting authorization for that
  node."
- **Execution, after approval commits:**
  - Activate the session delegation on `host`. If the space is activated,
    `hosting` is `existing` and the host SIWE is **never signed**.
  - If activation is `skipped`, sign the approved `hostSiwe` bytes exactly
    once (recording `hostSignedAt`), submit the hosting delegation, and
    activate again. `hosting` is then `created`, or `failed` if that fails.
- **Freshness:** if the node's staged `peerId` can expire before approval,
  prepare refreshes a plan older than the observed lifetime, and approve
  returns 409 `preparation_superseded`.
- **Scope:** the five-space account bootstrap is not part of this flow.

`hosting: "failed"` never leads to a further signature. The code is still
issued, and the app reports the space as unavailable (`SPACE_UNAVAILABLE`).

## Session proof

The code exchange, renewal and revocation each require one header:

```text
OpenKey-Session-Proof: <compact JWS>
```

Protected header:

```json
{"typ":"openkey-session-proof+jwt","alg":"EdDSA","kid":"<sessionJkt>"}
```

Payload (exactly these claims):

| Claim | Value |
|---|---|
| `jti` | Fresh random value, 16–128 characters. |
| `iat` | Unix seconds; accepted within ±60 s of server time. |
| `htm` | `POST` |
| `htu` | The exact discovered URL of the endpoint receiving the request. |
| `client_id` | The request's client. |
| `cred_hash` | `b64url(SHA-256(<credential>))`, where the credential is the literal `code` (code exchange) or `refresh_token` (renew, revoke). |

OpenKey verifies the signature against the public JWK **stored** at PAR, and
requires `kid` to equal the stored `sessionJkt`. A key supplied at redemption
is never used. The proof binds one credential, one endpoint and one client.
Replay is prevented because each credential is single-use and consumed under
lock, not by remembering `jti` values. A missing or invalid proof gets 401
`invalid_session_proof`.

### Session key thumbprint

`sessionJkt` is the RFC 7638 JWK thumbprint of the session key. This spec
fixes every choice RFC 7638 leaves open:

- **Input:** the RFC 8785 (JCS) serialization of exactly
  `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`. These are the three required
  OKP members (RFC 8037 §2), in lexicographic order, with no whitespace. The
  JWK's optional `kid`, and any other member, is **excluded**.
- **Hash:** SHA-256.
- **Encoding:** unpadded base64url.

Test vector (RFC 8037 Appendix A.3):

```text
x          = 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo
input      = {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
sessionJkt = kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
```

The same value results whether or not the PAR `session_key` carried a `kid`.

## Code exchange and token response

```text
POST /api/auth/oauth2/token
Content-Type: application/x-www-form-urlencoded
OpenKey-Session-Proof: <proof over the code>

grant_type=authorization_code&client_id=exo-native&code=<code>&redirect_uri=<uri>&code_verifier=<verifier>
```

better-auth deletes the code before it checks PKCE or runs OpenKey's token
hook. **Any failed exchange spends the code**, and the app must start a new
sign-in.

In the `customTokenResponseFields` hook, OpenKey:

1. loads the request from the code's stored `tinycloud_request`. A code with
   the delegation scope but no request reference gets `invalid_grant`;
2. verifies the session proof (401 `invalid_session_proof`);
3. locks consent `FOR SHARE`, which must exist and include
   `tinycloud:delegation`, then generation `FOR SHARE`, which must equal
   `request.consentGeneration`. Otherwise it returns `invalid_grant`;
4. redeems the request atomically:
   `UPDATE … SET status = 'REDEEMED' WHERE id = ? AND status = 'APPROVED' AND userId = ? AND clientId = ? AND codeChallenge = ? AND redirectUri = ?`.
   Zero rows gets `invalid_grant`, so of two concurrent redemptions exactly
   one succeeds;
5. computes `absoluteExpiresAt = now + grantLifetimeSeconds` from the
   **current** ceiling, and requires the approved delegation's `expiresAt ≤
   absoluteExpiresAt`. If the grant lifetime shrank after approval so that
   the delegation would outlive its grant, it returns `invalid_grant`. It then
   inserts a `TinyCloudNativeGrant` (consent id, consent generation, key,
   session JWK, permissions, TTL, host, `absoluteExpiresAt`), and commits. After the hook returns, the provider
   creates the refresh-token row itself, outside OpenKey's transaction. Its
   `generateRefreshToken` callback writes the new token's hash to
   `grant.refreshTokenHash` (`WHERE refreshTokenHash IS NULL`). OpenKey
   neither locks nor inserts token rows during code exchange.

If anything fails after step 4, the grant is left unlinked or pointing at no
token. Renewal requires a live matching token row, so it fails closed, and
the user signs in again.

Success (`Cache-Control: no-store`):

```json
{
  "access_token": "<opaque>",
  "token_type": "Bearer",
  "expires_in": 300,
  "expires_at": 1791374700,
  "refresh_token": "<opaque>",
  "scope": "openid offline_access tinycloud:delegation",
  "id_token": "<JWT, when openid was granted>",
  "authorization_details": [{
    "type": "tinycloud_delegation",
    "session_key": {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
    "permissions": [ … approved entries … ],
    "ttl_seconds": 3600
  }],
  "tinycloud_delegation": {
    "version": 1,
    "grantId": "<id>",
    "address": "0x…",
    "chainId": 1,
    "ownerDid": "did:pkh:eip155:1:0x…",
    "spaceId": "tinycloud:pkh:eip155:1:0x…:applications",
    "verificationMethod": "did:key:z6Mk…#z6Mk…",
    "siwe": "<exact signed SIWE>",
    "signature": "0x<EIP-191 signature>",
    "delegationHeader": {"Authorization": "<TinyCloud delegation>"},
    "delegationCid": "<CID>",
    "issuedAt": "2026-10-07T12:00:00.000Z",
    "expiresAt": "2026-10-07T13:00:00.000Z",
    "renewableUntil": "2026-11-06T11:55:00.000Z",
    "permissions": [ … approved entries … ],
    "tinycloudHost": "https://tee.node.tinycloud.xyz",
    "hosting": "existing"
  }
}
```

- `expires_in` and `expires_at` describe the access token, which lasts 300
  seconds. The refresh token lasts 7 days.
- `renewableUntil` is `absoluteExpiresAt − 300 s`, the last time a renewal can
  succeed.
- `hosting` is `existing`, `created` or `failed`.
- OpenKey never returns or stores the session private key.

**Native delegation clients cannot refresh the OpenKey access token.** The
provider's `refresh_token` grant refuses their refresh tokens
([interception](#provider-refresh-and-revoke-interception)). Renewal returns
only a new refresh token and delegation, with no access token or ID token.
After `expires_in` (300 s), an app that needs OpenKey API access (for example
`userinfo`) must sign in again through the browser. The refresh token is used
only to renew and revoke the TinyCloud delegation. SDKs must not offer an
access-token refresh for these clients.

Before using the delegation, the client checks that:

- `verificationMethod` is the DID of its own session key;
- `expiresAt` is in the future. If less than the renewal lead remains, it
  renews immediately;
- `permissions` is a subset of what it requested;
- `tinycloudHost` is the host it expects;
- `siwe` and `signature` reproduce `delegationHeader` and `delegationCid`.

Code-exchange errors:

| HTTP | `error` | Cause |
|---|---|---|
| 400 / 401 | provider errors (`invalid_request`, `invalid_client`, `invalid_verification`) | Unknown, expired or reused code; PKCE failure; redirect URI mismatch. |
| 401 | `invalid_session_proof` | Missing, malformed, wrongly signed or stale proof; wrong `htu`, `client_id` or `cred_hash`. |
| 400 | `invalid_grant` | No approved request, already redeemed, consent missing or withdrawn, generation changed. |
| 503 | `temporarily_unavailable` | Lock contention. The provider has already deleted the code, so **this code cannot be retried**: the client starts a new browser authorization. |

## Renewal

```text
POST /api/auth/oauth2/tinycloud/renew
Content-Type: application/x-www-form-urlencoded
OpenKey-Session-Proof: <proof over the refresh token, htu = renew endpoint>

client_id=exo-native&refresh_token=<current refresh token>[&siwe_nonce=<nonce>][&authorization_details=<JSON>]
```

- The optional `authorization_details` has the PAR shape. Its `session_key`
  must equal the grant's key, and its `permissions` must be a subset of the
  approved set. It cannot set `ttl_seconds`.
- The optional `siwe_nonce` follows the PAR rules.
- Duplicate form keys are refused.

Processing:

1. Hash the token. Look up the grant without a lock by
   `refreshTokenHash = h OR previousRefreshTokenHash = h`. No grant →
   401 `invalid_session_proof`, no side effects. This is the same response as
   a bad proof in step 2, so a caller without a valid proof cannot learn
   whether a token is a live native token. Native revoke behaves the same
   way.
2. Verify the proof against the grant's stored JWK, and `client_id` against
   the grant. Failure → 401 `invalid_session_proof`, no side effects.
3. Lock consent by `(userId, clientId)` `FOR SHARE`; if it is missing, return
   `consent_required`. Then lock generation `FOR SHARE`; it must equal
   `grant.consentGeneration`, otherwise `consent_required`. Then lock the
   grant `FOR UPDATE` and **revalidate**: the hash must still be current or
   previous, and the status `ACTIVE`. Otherwise `invalid_grant`.
4. If `h` is the **previous** hash:
   - within 30 s of `rotatedAt` → 409 `renewal_conflict`, no side effects
     (two renewals raced; reload the stored token);
   - otherwise this is refresh-token reuse: revoke the grant
     (`refresh_reuse`), delete its token rows, and return `invalid_grant`.
5. The token row must exist, be unrevoked and unexpired, and match the
   grant.
6. Policy, rechecked on every renewal:
   - `now < absoluteExpiresAt − 300 s`, otherwise `consent_required`;
   - the client is still enabled and has a ceiling, the approved (or
     requested) permissions are still inside the **current** ceiling, and SQL
     is still allowed (host in `TINYCLOUD_SQL_ISOLATED_HOSTS`). Otherwise
     `consent_required`;
   - the canonical key is still `grant.keyId`, otherwise `consent_required`;
   - the user's key-control mode is not `USER_CONTROLLED_EXCLUSIVE`, and the
     app isn't blocked ("block new signatures"). Otherwise `access_denied`;
   - `now ≥ lastRenewedAt + min(60 s, ttl/4)`. Otherwise the response is
     429 `renewal_too_soon` with `Retry-After: <n>`, where `n` is the whole
     number of seconds until that time, rounded up and at least 1. Nothing
     changes, and the presented token stays current. The SDK reports
     `RENEWAL_TOO_SOON` with `retryAfterSeconds = n`; the client waits `n`
     seconds and retries with the same token, without the generic backoff;
   - any requested subset is within the approved set, otherwise
     `consent_required`.
7. Sign a fresh session SIWE for the **same** session DID, covering the
   approved set or the requested subset, with the
   [renewal TTL](#ttl-rules). Signing happens inside the transaction.
8. Rotate:
   - mark the old token row revoked;
   - insert a new row in better-auth's format (stored token = SHA-256
     b64url, 7-day expiry), with the same `clientId`, `userId` and scopes as
     the original row, including `tinycloud:delegation`;
   - on the grant, set `previousRefreshTokenHash = h`, set
     `refreshTokenHash` to the new hash, and update `rotatedAt`,
     `lastRenewedAt` and `renewCount`;
   - write the audit row `native_renew`.
9. Commit and respond:

```json
{
  "refresh_token": "<new opaque token>",
  "expires_in": 604800,
  "tinycloud_delegation": {
    "version": 1,
    "grantId": "<same id>",
    "verificationMethod": "<same session did:key URL>",
    "siwe": "<new signed SIWE>",
    "signature": "0x…",
    "delegationHeader": {"Authorization": "<new delegation>"},
    "delegationCid": "<new CID>",
    "issuedAt": "…",
    "expiresAt": "…",
    "renewableUntil": "<unchanged>",
    "permissions": [ … ],
    "tinycloudHost": "https://tee.node.tinycloud.xyz",
    "hosting": "existing",
    "address": "0x…",
    "chainId": 1,
    "ownerDid": "…",
    "spaceId": "…"
  }
}
```

The `tinycloud_delegation` object has the same shape as in the token response.
Here `expires_in` is the new refresh token's lifetime. The client must persist
the new refresh token before it reports the renewal as done.

There is no idempotent replay. If a renewal response is lost, the old token
becomes "previous": retrying within 30 s gets `renewal_conflict`, and retrying
later revokes the grant. Either way, the user signs in again.

Renewal never accepts a new session key, a broader permission set or a longer
TTL. Any of those requires a new browser authorization.

## Native revocation

```text
POST /api/auth/oauth2/tinycloud/revoke
Content-Type: application/x-www-form-urlencoded
OpenKey-Session-Proof: <proof over the refresh token, htu = revoke endpoint>

client_id=exo-native&refresh_token=<current or previous refresh token>
```

- No grant, or no valid proof → 401 `invalid_session_proof`, with **no side
  effects**.
- With a valid proof, OpenKey uses the renewal lock order (consent if present
  → generation → grant `FOR UPDATE`, revalidated by current or previous
  hash). It sets the grant to `REVOKED` (`client_signout`), deletes its
  current and previous refresh-token rows and their access tokens, and
  returns `200 {}`.
- Revoking an already revoked grant with a valid proof returns `200 {}`.
- Only this device's grant is affected. Other devices of the same user and
  client keep working.

SDK `signOut()` calls this endpoint and then wipes the stored session key and
tokens. Already-issued delegations stay valid until `expiresAt`
([Remaining limits](#remaining-limits)).

## TTL rules

| Quantity | Rule |
|---|---|
| `request_uri` | 90 s, single use |
| Native request (`request.expiresAt`) | 10 min after PAR. Prepare, approve and deny refuse an expired request. |
| Authorization code | 10 min, single use; spent by any exchange attempt |
| Access token | 300 s |
| Refresh token | 7 days per token. Every renewal issues a new 7-day token, so the real bound on renewal is the grant's `absoluteExpiresAt`, not any one token's expiry. |
| Grant (`absoluteExpiresAt`) | Code exchange + the ceiling's `grantLifetimeSeconds` (default 30 days). Fixed; renewal never extends it. |
| Last renewal | Before `absoluteExpiresAt − 300 s` (`renewableUntil`) |
| Initial delegation TTL | `min(ttl_seconds or ceiling, ceiling.maxDelegationTtlSeconds, ceiling.grantLifetimeSeconds)`, computed at prepare and rechecked against the current ceiling at approve. Counted from the moment of signing at approve. Stored as `grant.ttlSeconds`. Code exchange refuses a delegation whose `expiresAt` is past the new grant's `absoluteExpiresAt`. |
| Renewal `Retry-After` (429) | Whole seconds until `lastRenewedAt + min(60 s, ttl/4)`, rounded up, at least 1 |
| Renewed delegation TTL | `min(grant.ttlSeconds, current ceiling.maxDelegationTtlSeconds, absoluteExpiresAt − now)` |
| Minimum renewal interval | `min(60 s, ttl/4)` after `lastRenewedAt` |
| Rotation conflict window | 30 s after `rotatedAt` |
| Session proof `iat` | ±60 s |

The renewal formula means:

- raising the ceiling later never lengthens a grant's delegations: an
  approved 300 s stays 300 s under a 24 h ceiling;
- lowering the ceiling shortens the next renewal;
- no delegation outlives its grant. That holds for the first delegation
  too: its TTL is capped by the grant lifetime, and code exchange checks it
  again against the current lifetime.

Clients schedule renewal at `max(expiresAt − lead, lastRenewAt + 60 s)` plus
0–10 s of jitter, where `lead = min(10 min, lifetime/4)`.

## Consent generation and withdrawal

The table `tinycloud_native_consent_generation (userId, clientId, generation
BIGINT, PRIMARY KEY (userId, clientId))` holds one counter for each user and
client. It ties every code and grant to the consent that was current when the
user approved.

- **Approve** records the current generation on the request. Doing this at
  approval rather than at code exchange is deliberate: it stops a code
  approved under one consent from attaching to a later consent.
- **Code exchange** requires the request's generation to still be current,
  and copies it to the grant.
- **Renewal** requires the grant's generation to still be current.

Database triggers implement withdrawal:

- `AFTER DELETE ON oauth_consent`;
- `AFTER UPDATE OF scopes ON oauth_consent … WHEN NOT ('tinycloud:delegation' = ANY(NEW.scopes))`.

While holding the consent row lock, each trigger does the following in one
transaction, in this order:

1. increments the generation for `(userId, clientId)`;
2. sets that user and client's `RESOLVED` and `APPROVED` requests to
   `WITHDRAWN`;
3. sets their grants to `REVOKED` (`consent_withdrawn`);
4. deletes those grants' current and previous refresh-token rows, and the
   access tokens whose `refreshId` points at them.

The triggers fire on every path: the provider's consent delete and update
endpoints, a user-deletion cascade, account controls, and direct SQL.
`TinyCloudNativeGrant.clientId` references `oauth_client.clientId` with
`ON DELETE CASCADE`, so deleting the client removes its grants.

Consequences:

- After a delete and re-consent, the new consent has a new generation. An old
  code, an old refresh token or a pending approved request cannot use it.
- A renewal in flight is serialized against withdrawal by the lock order. If
  renewal commits first, withdrawal then deletes the token renewal just
  created.
- The "block new signatures" account control (extended to delegation
  consents) stops renewals without deleting consent.
- Withdrawal cannot recall a delegation that was already signed. It stays
  usable at the node until `expiresAt`.

The deploy verifier (`scripts/verify-tc-488-cutover.ts`) checks that the
generation table and both triggers exist.

## Global lock order

Every transaction that touches native-delegation state takes row locks in
this order and only this order:

```text
oauth_consent → tinycloud_native_consent_generation → TinyCloudNativeRequest
  → TinyCloudNativeGrant → oauth_refresh_token / oauth_access_token
```

A transaction may skip a level, but never goes back up to one. Every
transaction starts with `SET LOCAL lock_timeout = '5s'`.

| Operation | Locks |
|---|---|
| Prepare / approve | consent `FOR SHARE` (may be missing) → generation (`INSERT … ON CONFLICT DO NOTHING`, then `FOR SHARE`) → request `FOR UPDATE` |
| Code exchange | consent `FOR SHARE` → generation `FOR SHARE` → request (atomic `UPDATE`) → grant insert. The provider writes the refresh-token row afterwards, outside this transaction, and `generateRefreshToken` links it to the grant. |
| Renew / native revoke | consent `FOR SHARE` → generation `FOR SHARE` → grant `FOR UPDATE` → token rows |
| Withdrawal trigger | consent (held by the `DELETE`/`UPDATE`) → generation `UPDATE` → requests → grants → token rows |

Anything read before taking a lock is checked again after the lock is held.
PostgreSQL SQLSTATE `40P01` (deadlock) and `55P03` (lock timeout) roll the
transaction back and return:

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 2

{"error":"temporarily_unavailable"}
```

For **renew and native revoke**, the transaction has fully rolled back. The
client may retry with the same refresh token and a fresh proof after
`Retry-After`.

**Code exchange is the exception.** better-auth deletes the authorization code
before OpenKey's hook runs, and that deletion is outside the rolled-back
transaction. Retrying with the same code gets the provider's
`invalid_verification`. On a 503 from code exchange, the SDK reports
`TEMPORARILY_UNAVAILABLE` and never resends that code. Calling `signIn` again
starts a new PAR and browser authorization.

## Provider refresh and revoke interception

better-auth's own endpoints would otherwise bypass the native rules. Two
Hono interceptors run before `auth.handler` and share one parser:

- form-urlencoded, plus any JSON media type the provider accepts;
- the client comes from the `Authorization: Basic` header first, then the
  body's `client_id`;
- **duplicate keys are refused**;
- an unparseable media type passes through only if the provider would also
  reject it; otherwise the request is refused;
- the token is **normalized exactly as the provider endpoint behind the
  interceptor would normalize it**, before any lookup (see below);
- a token is looked up in every place it could match, whatever
  `token_type_hint` says: refresh-token rows **including revoked rows**,
  grants' current and previous hashes, and access-token rows.

**Token normalization.** If the lookup normalized differently from the
provider, a token the interceptor cannot find would pass through, and the
provider would then find it. In 1.6.10:

- `/oauth2/revoke` strips a leading `Bearer ` from `token`, then applies
  `decodeRefreshToken` (configured `prefix.refreshToken` removal and
  `formatRefreshToken.decrypt`) for the refresh-token lookup. For the
  access-token lookup it applies `prefix.opaqueAccessToken` removal.
- The `refresh_token` grant applies `decodeRefreshToken` only; it does not
  strip `Bearer `.

The revoke interceptor **refuses** any `token` that starts with `Bearer `,
with 400 `invalid_request` and no side effects; no legitimate RFC 7009 caller
sends one. Both interceptors apply the provider's remaining normalization by
calling the same functions with the same provider options. OpenKey currently
configures no `prefix` or `formatRefreshToken`, but the interceptor follows
the options rather than assuming that. A provider upgrade that changes
normalization must update the interceptor; the regression tests below catch
drift.

**Native credentials are classified by how they were issued, not by the
client's current configuration.** A token is **native** if any of these
holds:

- its refresh-token row (revoked or not) has `tinycloud:delegation` in its
  scopes. Code exchange issues rows with the request's scopes, and renewal
  copies them;
- its hash is a `TinyCloudNativeGrant`'s current or previous refresh-token
  hash, whatever the grant's status;
- it is an access token whose scopes include `tinycloud:delegation`, or
  whose `refreshId` points at a native refresh-token row.

A client is a **delegation client** if delegation is currently enabled for
it. This only matters for the requesting side of the ownership check.
Disabling delegation on a client, or removing its `tinycloud:delegation`
scope, does **not** reopen the provider's refresh path for tokens it already
issued. Those tokens stay native, and renewal refuses them with
`consent_required` because the client is no longer enabled.

### `POST /api/auth/oauth2/token`, `grant_type=refresh_token`

If the presented token is native, the request gets 400 `invalid_grant` with
`error_description` "use the renew endpoint", whatever the client's current
configuration and whatever `scope` the request asks for. The provider never
rotates or exchanges a native token.

### `POST /api/auth/oauth2/revoke` (A2)

better-auth 1.6.10 handles a **revoked** refresh token before it checks that
the token belongs to the requesting client. In that branch it deletes every
refresh token for the token's user **and the supplied `client_id`**. Without
interception, anyone holding any revoked refresh token for user U could send
it with Exo's public `client_id` and log out every Exo device of U, with no
proof and no secret.

The interceptor decides before the provider runs:

| Presented token | Requesting client | Result |
|---|---|---|
| `token` starting with `Bearer ` | any | 400 `invalid_request`, no side effects. |
| Native refresh token (any state; classified as above) | any | 400 `unsupported_token_type`, no side effects. Use the native revoke endpoint. |
| Refresh token (any state) owned by client A | client B ≠ A | 400 `invalid_request` ("token was not issued to this client"), no side effects. |
| Non-native refresh token | the client that owns it | Passed to the provider. |
| Access token owned by the requesting client | same | Passed to the provider, which deletes only that access token. |
| Access token owned by another client | — | 400 `invalid_request`, no side effects. |
| Not found | — | Passed to the provider, which returns 200 with no side effects (RFC 7009). |

The first matching row applies. Native classification protects tokens
issued to a native client; the ownership check protects a delegation client
when it is named as the requesting client. Regression cases:

- An ordinary client's revoked refresh token, sent with a native client's
  `client_id`, leaves both of that user's native devices' tokens intact.
- The same revoked ordinary-client token, sent as `token=Bearer <token>`
  with Exo's `client_id`, gets 400 and leaves every Exo token intact.
- Device A's rotated (revoked) native token, sent to the provider endpoint,
  gets 400 and changes nothing, and device B can still renew.
- After an admin disables delegation for a client, a native refresh token it
  issued, sent to the provider refresh grant with `scope=openid
  offline_access`, gets 400 `invalid_grant` and no tokens are issued.

## CORS

The WebView origins `capacitor://localhost` (iOS) and `https://localhost`
(Android) call the public endpoints directly. These paths are registered
before the global CORS middleware, and the global middleware skips them:

```text
/.well-known/oauth-authorization-server*
/.well-known/openid-configuration
/api/auth/.well-known/*
/api/auth/oauth2/par
/api/auth/oauth2/token
/api/auth/oauth2/tinycloud/*
```

Policy: `cors({ origin: '*', credentials: false, allowMethods: ['GET', 'POST',
'OPTIONS'], allowHeaders: ['Content-Type', 'OpenKey-Session-Proof'],
exposeHeaders: ['Retry-After'] })`. Responses carry
`Access-Control-Allow-Origin: *`, `Access-Control-Expose-Headers:
Retry-After`, and **no** `Access-Control-Allow-Credentials`. `Retry-After` is
not a CORS-safelisted response header. Without the expose header, WebView
JavaScript reads `null` for it on the 429 (`renewal_too_soon`) and 503
(`temporarily_unavailable`) responses, so the tests read it through `fetch`
from a `capacitor://localhost` origin for both. These endpoints never read cookies; they
authenticate with PKCE, the session proof and single-use credentials.

Every other route keeps the restricted OpenKey-origin policy with
credentials. That includes the cookie-authenticated
`/api/oauth/tinycloud/requests/*`, `/api/auth/oauth2/consent` and account
routes, and the provider's `/api/auth/oauth2/revoke`.

## Error reference

| Endpoint | HTTP | `error` |
|---|---|---|
| PAR | 400 / 401 | `invalid_request`, `invalid_scope`, `invalid_authorization_details`, `unauthorized_client`, `invalid_client` |
| Authorize | `https://api.openkey.so/api/auth/error` | `invalid_request_uri`, or `invalid_request` for a failed `tinycloud_request` binding (no redirect to the app) |
| Callback | redirect | `access_denied` (with `state`, `iss`) |
| Prepare / approve / deny | 401 / 403 / 404 / 409 | `unauthorized`, `request_user_mismatch`, `request_not_found`, `request_not_pending`, `preparation_superseded`, `preparation_mismatch` |
| Code exchange | 400 / 401 | provider errors, `invalid_session_proof`, `invalid_grant` |
| Renew | 400 | `invalid_grant` (used, expired or reused token; revoked grant). Returned only after a valid proof. |
| Renew | 400 | `consent_required` (consent withdrawn or changed, grant near its end, ceiling shrank, key changed, subset too wide) |
| Renew | 400 | `access_denied` (exclusive key-control mode or app blocked) |
| Renew | 401 | `invalid_session_proof` (bad proof, or unknown token) |
| Renew | 409 | `renewal_conflict` (a previous token within 30 s of rotation) |
| Renew | 429 | `renewal_too_soon` (`Retry-After` in seconds) |
| Native revoke | 401 | `invalid_session_proof` (bad proof, or unknown token) |
| Provider refresh | 400 | `invalid_grant` (native token, whatever the client's current configuration) |
| Provider revoke | 400 | `unsupported_token_type` (native token), `invalid_request` (ownership mismatch, or `Bearer `-prefixed token) |
| Any locked operation | 503 | `temporarily_unavailable` (`Retry-After: 2`). For code exchange the code is already spent and cannot be retried. |

### SDK mapping

The SDK (TC-774) error codes are `USER_CANCELLED`, `ACCESS_DENIED`,
`STATE_MISMATCH`, `CONSENT_REQUIRED`, `INVALID_GRANT`, `RENEWAL_CONFLICT`,
`RENEWAL_TOO_SOON` (with `retryAfterSeconds`), `SPACE_UNAVAILABLE`,
`TEMPORARILY_UNAVAILABLE`, `NOT_SIGNED_IN`, `NETWORK`, `SERVER` and
`UNAVAILABLE`.

| Server outcome | SDK code | Behavior |
|---|---|---|
| Sheet closed without a callback (including the `invalid_request_uri` error page) | `USER_CANCELLED` | Terminal for this attempt. |
| Callback `error=access_denied` | `ACCESS_DENIED` | Terminal. |
| Callback `state` or `iss` mismatch | `STATE_MISMATCH` | Terminal. |
| `invalid_session_proof` (401) from code exchange, renew or native revoke | `INVALID_GRANT` | **Terminal, no retry.** The code, or the refresh token and its grant, is unusable for this key. |
| `invalid_grant`, or provider code-exchange errors | `INVALID_GRANT` | Terminal, no retry. |
| `consent_required` | `CONSENT_REQUIRED` | Terminal; a new browser sign-in is needed. |
| `access_denied` from renew | `ACCESS_DENIED` | Terminal. |
| `renewal_conflict` (409) | `RENEWAL_CONFLICT` | Reload the stored token; retry once. |
| `renewal_too_soon` (429) | `RENEWAL_TOO_SOON` | Wait `retryAfterSeconds`, then retry with the same token. |
| `temporarily_unavailable` (503) from renew or native revoke | `TEMPORARILY_UNAVAILABLE` | Retry the same token with a fresh proof after `Retry-After`. |
| `temporarily_unavailable` (503) from code exchange | `TEMPORARILY_UNAVAILABLE` | Never resend the code; a new `signIn` starts a fresh authorization. |
| `hosting: "failed"` in a successful response | `SPACE_UNAVAILABLE` | Terminal for this session. |
| Fetch failure | `NETWORK` | Retryable. |
| Any other non-2xx or malformed response | `SERVER` | Not retried automatically. |
| No stored session | `NOT_SIGNED_IN` | — |
| Platform without the native plugin | `UNAVAILABLE` | — |

"Terminal" from renew means a local sign-out. From native revoke, it means the
server-side grant is already unusable, so `signOut` still wipes the local key
and tokens and resolves.

## TinyCloud node dependency (TC-780)

SQL capabilities are only safe on a node that isolates SQL and DuckDB
databases by full path. Released tinycloud-node (v1.4.10, and `main` before
the fix) does not:

- `db_name_from_path` picks a database by the **last path segment**, keyed by
  `(space, name)`. So `appA/connectors` and `appB/connectors` share one
  database in the shared `applications` space.
- Invocation authorization uses descendant `extends`, so a grant for
  `appA/connectors` also authorizes `appA/connectors/private`, which opens
  the database `private`.
- DuckDB has the same flaw.

The fix (TC-780):

- the database identity is the normalized full path;
- a SQL or DuckDB grant without a trailing `/` matches **exactly**;
- slash-terminated and pathless grants stay prefix grants, so web manifests
  (`appId/`) keep working.

Legacy data moves under a write-fenced, alias-based migration:

- Legacy artifacts are found with each engine's exact old selector, including
  the service.
- An explicit alias maps a full-path identity to a legacy physical artifact.
  **No path resolves to a legacy physical name directly.** Unattributed and
  ambiguous artifacts stay quarantined until an authorized mapping exists.
- The release is not auto-deployed until the fence, checkpoint, backup and
  alias transaction are complete. The fixed binary is deployed, and any
  rollback happens, while the fence is up.

OpenKey's gate is `TINYCLOUD_SQL_ISOLATED_HOSTS`. A ceiling with `sql` is
refused at enablement, and a SQL permission is refused at PAR and at renewal,
unless the ceiling's host is listed there. A host is added only after its
cutover has been verified. Until then, native clients can be enabled with
`sql: null` and KV only.

## Threat model

Assets: the user's canonical key (in the TEE), the ability to make it sign,
and the data in the user's `applications` space. The native app is a public
client, so OpenKey cannot authenticate it.

| Threat | Outcome |
|---|---|
| Refresh token stolen (current or rotated) | **No effect.** Renew, native revoke and reuse detection all require a session proof first. The provider refresh and revoke endpoints refuse delegation tokens without side effects, and the ownership check stops a token from being replayed under another `client_id`. |
| Refresh token and session private key stolen | The attacker can renew within the approved set and TTL until `renewableUntil` (the grant's absolute expiry), withdrawal, block or native revoke. Reuse detection ends it early only if the legitimate device presents the attacker's *previous* token; see [Stolen refresh tokens](#stolen-refresh-tokens). Each rotation issues a fresh 7-day token, so the token expiry is not a bound. No new capabilities, spaces, nodes or signatures. |
| Delegation stolen without the session key | Useless. Every invocation must be signed by the session key. |
| Delegation and session key stolen | Usable until `expiresAt` (at most the approved TTL, 1 h by default). It cannot be recalled before then. |
| Authorization response intercepted | See [Interception versus impersonation](#interception-versus-impersonation-rfc-8252-86). The interceptor lacks the PKCE verifier and the session key. |
| Another app uses Exo's `client_id` | See [Interception versus impersonation](#interception-versus-impersonation-rfc-8252-86). Not prevented; limited. |
| Consent phishing by an arbitrary client | Only admins can enable delegation; dynamic and console clients cannot get the scope; each client is confined to `<appId>/` paths on one allowlisted node. |
| Stale or swapped consent preview | Immutable revisions, the digest, exact byte echo, user binding and a canonical-key recheck under lock. A tab can approve only the bytes it displayed. |
| Old code or grant after consent withdrawal | Generation binding: withdrawal revokes grants and pending requests in the same transaction, and re-consent cannot revive them. |
| Replay | Single-use `request_uri`, single-use code (atomic redemption), proofs bound to one credential and endpoint and consumed under lock, refresh rotation with one-step reuse detection, `iss`, `state`, SIWE nonce. |
| Cross-device logout through the provider revoke endpoint | Closed by the A2 ownership check and refusal of delegation tokens. |
| Hosting authority to a hostile node | Host comes only from the admin ceiling and the trusted allowlist; separately disclosed; digest-bound; signed at most once and only if the space is missing. |
| Cross-app SQL access on the node | Closed only on TC-780-fixed nodes; enforced by `TINYCLOUD_SQL_ISOLATED_HOSTS`. |

### Stolen refresh tokens

A native refresh token is useless without its session key:

- The renew and native revoke endpoints verify the proof **before** acting on
  the token. Before the proof is verified, the only lookup is a read, so
  failure has no side effects. An unknown token gets the same 401 as a bad
  proof, so the endpoints don't reveal which tokens are live.
- Reuse detection (revoking a grant whose previous token is presented after
  30 s) runs only after a valid proof. An attacker who has only a rotated
  token therefore cannot use reuse detection to log the user out.
- The provider's `grant_type=refresh_token` and `/oauth2/revoke` refuse native
  tokens, revoked rows included, even after delegation is disabled for the
  client. Provider 1.6.10's revoked-token branch would otherwise delete every
  refresh token for the user and client. The A2 ownership check also covers a
  revoked token from **another** client sent with the native `client_id`,
  with or without a `Bearer ` prefix.

If the session key is stolen too, the attacker becomes a second holder of the
same grant. Reuse detection is **one step deep**: renewal looks up only the
grant's current and previous hashes. So:

- If the attacker rotates once (A→B) and the device then presents A, A is
  the previous token. After 30 s that revokes the grant (`refresh_reuse`),
  ending both copies.
- If the attacker rotates twice or more (A→B→C, for example while the device
  is offline) and the device then presents A, A is neither current nor
  previous. The device gets 401 `invalid_session_proof` and signs out
  locally. **The attacker's grant is not revoked.**
- Each rotation issues a fresh 7-day refresh token, so an attacker who keeps
  renewing is never stopped by token expiry.

The real bounds on a stolen key and token are therefore:

- the grant's `absoluteExpiresAt` (at most `grantLifetimeSeconds`, 30 days by
  default; renewal stops 300 s before it);
- consent withdrawal or deletion;
- "block new signatures";
- native revoke;
- disabling the client.

The attacker never gains more than the device had: the same DID, permissions
and TTL.

Keeping the whole token family to detect deeper reuse is not part of this
version. It would need a per-grant history of every issued token hash, kept
until the grant expires, plus a lookup on every renewal and revoke. Because
the session key must be stolen too, and the grant is bounded and revocable, we
document the limit and rely on absolute grant expiry plus revocation. A user
who signs in again after an unexpected sign-out should revoke the app from the
account page.

### Interception versus impersonation (RFC 8252 §8.6)

Two different attacks use the private-use redirect scheme
(`xyz.tinycloud.exo://`):

- **Interception:** a malicious app registers the same scheme and receives
  the redirect from the user's legitimate sign-in.
  - On iOS, ASWebAuthenticationSession returns the callback only to the app
    that started the session.
  - On Android, more than one app can claim a custom scheme. The interceptor
    gets `code`, `state` and `iss`, but redeeming the code needs the PKCE
    verifier and a proof signed by the session key registered at PAR. Both
    stay inside the legitimate app, so the stolen code cannot be redeemed.
    Any attempt with it spends the code, which costs the user one retry.
- **Impersonation:** a malicious app starts its **own** flow with Exo's
  public `client_id`, its own PKCE pair, its own session key and the shared
  scheme. As RFC 8252 §8.6 notes, nothing in OAuth for public clients
  distinguishes it from the real app. PKCE and the session proof both pass,
  because the attacker created both. If the user approves, the attacker gets
  a delegation within Exo's ceiling. What limits it:
  - consent is always shown (`prompt=consent`), with the label **Unverified
    app**, the return scheme, the node, the exact capabilities and any
    hosting operation;
  - the ceiling: `<appId>/` paths only, on one node, in the `applications`
    space, with no other spaces and no arbitrary signing;
  - a short delegation TTL;
  - withdrawal and blocking from the account page.

  Claimed HTTPS redirects (Universal Links / App Links) and a verified-app
  label would let OpenKey tell apps apart. They are not part of this version.

### Why PKCE alone is not enough

PKCE binds code redemption to whoever started the authorization request.
That is all it does. It does not:

- identify or authenticate a public native app (it doesn't help against
  impersonation);
- bind the issued refresh token to a device key (a stolen token would work
  anywhere);
- protect anything after the code is redeemed (renew, revoke, reuse
  detection);
- limit what OpenKey signs (that is the ceiling and the consent preview);
- prevent an old approval from outliving the consent it was given under
  (that is the generation).

The session proof adds device-key binding to the code, renewal and
revocation. The ceiling, consent display and generation binding cover the
rest.

### Remaining limits

- **Device or JavaScript compromise.** In v1 the session private JWK and the
  refresh token are both handled in WebView JavaScript. They are stored in the
  Keychain (`AfterFirstUnlockThisDeviceOnly`) or behind an Android Keystore
  wrapping key, but held in memory while in use. Code running in the WebView
  can take both.
- **Signed delegations cannot be recalled before they expire.** Withdrawal,
  block and sign-out stop renewal, but a delegation already issued stays
  valid at the node until `expiresAt` (at most the approved TTL, 1 h by
  default).
- **Private-scheme impersonation** remains possible. Consent and the ceiling
  limit it; they do not prevent it.
- **Lost renewal response.** It forces a new sign-in; there is no idempotent
  replay.
- **One-step reuse detection.** An attacker holding the session key who has
  rotated two or more times is not detected when the device presents an older
  token. The bound is the grant's absolute expiry plus explicit revocation
  ([Stolen refresh tokens](#stolen-refresh-tokens)).
- **Lost code exchange.** A 503 or network failure during code exchange
  spends the code, and the user goes through the browser again.
- **KV `list`** on a node without TC-731 can reveal sibling key names outside
  the granted prefix. Production nodes must run a release that includes
  TC-731.
- **SQL on unfixed nodes** is unsafe; it is blocked by the
  `TINYCLOUD_SQL_ISOLATED_HOSTS` gate, not by the node.
- **Pinned provider internals.** The interceptors and hooks depend on
  better-auth 1.6.10's request parsing, revocation branch, token row format
  and hook order. `@better-auth/oauth-provider` is pinned exactly, and the
  interceptor tests act as tripwires on upgrade.
