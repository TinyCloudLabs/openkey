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

- The authorize guard refuses `tinycloud:delegation` unless the request came
  through a `request_uri` or carries the server-set `tinycloud_request`
  binding. For a delegation-enabled client, it also refuses an authorize
  request that omits `scope` and has no `request_uri`, because the provider
  would otherwise fall back to all of the client's scopes.
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
| `Issued At` / `Expiration Time` | Signing time / signing time + the delegation TTL ([TTL rules](#ttl-rules)) |
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
| `session_key` | yes | Public Ed25519 JWK: `{"kty":"OKP","crv":"Ed25519","x":"<b64url 32 bytes>"}`, optionally with a non-empty string `kid`. `x` must decode to exactly 32 bytes and re-encode to the same string. Private (`d`), `null`-valued or other members are refused. |
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
RFC 7638 thumbprint (`sessionJkt`), the session DID, the validated
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
consent screen always appears. An unknown, expired or reused `request_uri`
shows OpenKey's error page (`invalid_request_uri`) and does not redirect to
the app. The SDK reports a closed sheet without a callback as
`USER_CANCELLED`.

If the user isn't signed in, OpenKey sends them to `/auth/login` and then
resumes with the stored, resolved query. Login and the consent page run on
`https://openkey.so`.

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
4. builds the session SIWE with TTL = min(requested TTL, ceiling);
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
- the delegation lifetime and how long the app may keep renewing;
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
- `userId` equal to the session user;
- `revision === currentRevision`;
- a digest equal to the stored one;
- echoed bytes identical to the stored `sessionSiwe` and `hostSiwe`;
- the same canonical key;
- an unexpired SIWE.

It then records `request.consentGeneration` as the current
[consent generation](#consent-generation-and-withdrawal), signs `sessionSiwe`
with the canonical key, builds the delegation (`completeSessionSetup`), and
stores it. It sets `APPROVED` and `approvedRevision`, then commits. **No
canonical-key signature happens before this point.**

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
| 409 | `request_not_pending` | The status isn't `RESOLVED`, or the request expired. |
| 409 | `preparation_superseded` | `revision` isn't current: another tab prepared again, or the host plan was refreshed. Prepare again. |
| 409 | `preparation_mismatch` | Wrong digest, changed echoed bytes, changed canonical key, or expired SIWE. |
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
{"typ":"openkey-session-proof+jwt","alg":"EdDSA","kid":"<b64url RFC 7638 thumbprint of the session JWK>"}
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
5. inserts a `TinyCloudNativeGrant` (consent id, consent generation, key,
   session JWK, permissions, TTL, host, `absoluteExpiresAt = now +
   grantLifetimeSeconds`). `generateRefreshToken` then writes the new refresh
   token's hash to `grant.refreshTokenHash`
   (`WHERE refreshTokenHash IS NULL`).

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

Before using the delegation, the client checks that:

- `verificationMethod` is the DID of its own session key;
- `expiresAt` is in the future;
- `permissions` is a subset of what it requested;
- `tinycloudHost` is the host it expects;
- `siwe` and `signature` reproduce `delegationHeader` and `delegationCid`.

Code-exchange errors:

| HTTP | `error` | Cause |
|---|---|---|
| 400 / 401 | provider errors (`invalid_request`, `invalid_client`, `invalid_verification`) | Unknown, expired or reused code; PKCE failure; redirect URI mismatch. |
| 401 | `invalid_session_proof` | Missing, malformed, wrongly signed or stale proof; wrong `htu`, `client_id` or `cred_hash`. |
| 400 | `invalid_grant` | No approved request, already redeemed, consent missing or withdrawn, generation changed. |
| 503 | `temporarily_unavailable` | Lock contention. |

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
   400 `invalid_grant`, no side effects.
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
   - `now ≥ lastRenewedAt + min(60 s, ttl/4)`, otherwise 429
     `renewal_too_soon` with `Retry-After`;
   - any requested subset is within the approved set, otherwise
     `consent_required`.
7. Sign a fresh session SIWE for the **same** session DID, covering the
   approved set or the requested subset, with the
   [renewal TTL](#ttl-rules). Signing happens inside the transaction.
8. Rotate:
   - mark the old token row revoked;
   - insert a new row in better-auth's format (stored token = SHA-256
     b64url, 7-day expiry);
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
| Native request (PAR to consent) | 10 min |
| Authorization code | 10 min, single use; spent by any exchange attempt |
| Access token | 300 s |
| Refresh token | 7 days per token; rotated on every renewal |
| Grant (`absoluteExpiresAt`) | Code exchange + the ceiling's `grantLifetimeSeconds` (default 30 days). Fixed; renewal never extends it. |
| Last renewal | Before `absoluteExpiresAt − 300 s` (`renewableUntil`) |
| Initial delegation TTL | `min(ttl_seconds or ceiling, ceiling.maxDelegationTtlSeconds)`. Stored as `grant.ttlSeconds`. |
| Renewed delegation TTL | `min(grant.ttlSeconds, current ceiling.maxDelegationTtlSeconds, absoluteExpiresAt − now)` |
| Minimum renewal interval | `min(60 s, ttl/4)` after `lastRenewedAt` |
| Rotation conflict window | 30 s after `rotatedAt` |
| Session proof `iat` | ±60 s |

The renewal formula means:

- raising the ceiling later never lengthens a grant's delegations: an
  approved 300 s stays 300 s under a 24 h ceiling;
- lowering the ceiling shortens the next renewal;
- no delegation outlives its grant.

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
| Code exchange | consent `FOR SHARE` → generation `FOR SHARE` → request (atomic `UPDATE`) → grant insert → token rows |
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

The transaction has fully rolled back, so the client may retry with the same
credential after `Retry-After`. Renew needs a fresh proof `iat` if the old one
is more than 60 s old.

## Provider refresh and revoke interception

better-auth's own endpoints would otherwise bypass the native rules. Two
Hono interceptors run before `auth.handler` and share one parser:

- form-urlencoded, plus any JSON media type the provider accepts;
- the client comes from the `Authorization: Basic` header first, then the
  body's `client_id`;
- **duplicate keys are refused**;
- an unparseable media type passes through only if the provider would also
  reject it; otherwise the request is refused;
- a token is looked up in every place it could match, whatever
  `token_type_hint` says: refresh-token rows **including revoked rows**,
  grants' current and previous hashes, and access-token rows.

A client is a **delegation client** if delegation is enabled for it.

### `POST /api/auth/oauth2/token`, `grant_type=refresh_token`

If the presented token's row (revoked or not), or a grant's current or
previous hash, belongs to a delegation client, the request gets 400
`invalid_grant` with `error_description` "use the renew endpoint". The
provider never rotates these tokens.

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
| Refresh token (any state) owned by a delegation client | any | 400 `unsupported_token_type`, no side effects. Use the native revoke endpoint. |
| Refresh token (any state) owned by client A | client B ≠ A | 400 `invalid_request` ("token was not issued to this client"), no side effects. |
| Refresh token owned by an ordinary client | the same client | Passed to the provider. |
| Access token owned by the requesting client | same | Passed to the provider, which deletes only that access token. |
| Access token owned by another client | — | 400 `invalid_request`, no side effects. |
| Not found | — | Passed to the provider, which rejects it without side effects. |

The ownership check protects a delegation client whether it appears as the
token's owner or as the requesting client. Regression cases:

- An ordinary client's revoked refresh token, sent with a native client's
  `client_id`, leaves both of that user's native devices' tokens intact.
- Device A's rotated (revoked) native token, sent to the provider endpoint,
  gets 400 and changes nothing, and device B can still renew.

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
'OPTIONS'], allowHeaders: ['Content-Type', 'OpenKey-Session-Proof'] })`.
Responses carry `Access-Control-Allow-Origin: *` and **no**
`Access-Control-Allow-Credentials`. These endpoints never read cookies; they
authenticate with PKCE, the session proof and single-use credentials.

Every other route keeps the restricted OpenKey-origin policy with
credentials. That includes the cookie-authenticated
`/api/oauth/tinycloud/requests/*`, `/api/auth/oauth2/consent` and account
routes, and the provider's `/api/auth/oauth2/revoke`.

## Error reference

| Endpoint | HTTP | `error` |
|---|---|---|
| PAR | 400 / 401 | `invalid_request`, `invalid_scope`, `invalid_authorization_details`, `unauthorized_client`, `invalid_client` |
| Authorize | error page | `invalid_request_uri` (no redirect) |
| Callback | redirect | `access_denied` (with `state`, `iss`) |
| Prepare / approve / deny | 401 / 403 / 404 / 409 | `unauthorized`, `request_user_mismatch`, `request_not_found`, `request_not_pending`, `preparation_superseded`, `preparation_mismatch` |
| Code exchange | 400 / 401 | provider errors, `invalid_session_proof`, `invalid_grant` |
| Renew | 400 | `invalid_grant` (unknown, used, expired or reused token; revoked grant) |
| Renew | 400 | `consent_required` (consent withdrawn or changed, grant near its end, ceiling shrank, key changed, subset too wide) |
| Renew | 400 | `access_denied` (exclusive key-control mode or app blocked) |
| Renew | 401 | `invalid_session_proof` |
| Renew | 409 | `renewal_conflict` (a previous token within 30 s of rotation) |
| Renew | 429 | `renewal_too_soon` (`Retry-After`) |
| Native revoke | 401 | `invalid_session_proof` |
| Provider refresh | 400 | `invalid_grant` (delegation client token) |
| Provider revoke | 400 | `unsupported_token_type`, `invalid_request` (ownership mismatch) |
| Any locked operation | 503 | `temporarily_unavailable` (`Retry-After: 2`) |

The SDK (TC-774) maps these to `CONSENT_REQUIRED`, `INVALID_GRANT`,
`RENEWAL_CONFLICT`, `TEMPORARILY_UNAVAILABLE`, `ACCESS_DENIED`,
`STATE_MISMATCH`, `SPACE_UNAVAILABLE`, `USER_CANCELLED`, `NOT_SIGNED_IN`,
`NETWORK`, `SERVER` and `UNAVAILABLE`.

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
| Refresh token and session private key stolen | The attacker can renew within the approved set and TTL until the earliest of: the 7-day token expiry, `renewableUntil`, withdrawal, block, or the legitimate device's next renewal. That renewal presents the now-previous token, which revokes the grant (`refresh_reuse`). No new capabilities, spaces, nodes or signatures. |
| Delegation stolen without the session key | Useless. Every invocation must be signed by the session key. |
| Delegation and session key stolen | Usable until `expiresAt` (at most the approved TTL, 1 h by default). It cannot be recalled before then. |
| Authorization response intercepted | See [Interception versus impersonation](#interception-versus-impersonation-rfc-8252-86). The interceptor lacks the PKCE verifier and the session key. |
| Another app uses Exo's `client_id` | See [Interception versus impersonation](#interception-versus-impersonation-rfc-8252-86). Not prevented; limited. |
| Consent phishing by an arbitrary client | Only admins can enable delegation; dynamic and console clients cannot get the scope; each client is confined to `<appId>/` paths on one allowlisted node. |
| Stale or swapped consent preview | Immutable revisions, the digest, exact byte echo, user binding and a canonical-key recheck under lock. A tab can approve only the bytes it displayed. |
| Old code or grant after consent withdrawal | Generation binding: withdrawal revokes grants and pending requests in the same transaction, and re-consent cannot revive them. |
| Replay | Single-use `request_uri`, single-use code (atomic redemption), proofs bound to one credential and endpoint and consumed under lock, refresh rotation with reuse detection, `iss`, `state`, SIWE nonce. |
| Cross-device logout through the provider revoke endpoint | Closed by the A2 ownership check and refusal of delegation tokens. |
| Hosting authority to a hostile node | Host comes only from the admin ceiling and the trusted allowlist; separately disclosed; digest-bound; signed at most once and only if the space is missing. |
| Cross-app SQL access on the node | Closed only on TC-780-fixed nodes; enforced by `TINYCLOUD_SQL_ISOLATED_HOSTS`. |

### Stolen refresh tokens

A native refresh token is useless without its session key:

- The renew and native revoke endpoints verify the proof **before** acting on
  the token. Before the proof is verified, the only lookup is a read, so
  failure has no side effects.
- Reuse detection (revoking a grant whose previous token is presented after
  30 s) runs only after a valid proof. An attacker who has only a rotated
  token therefore cannot use reuse detection to log the user out.
- The provider's `grant_type=refresh_token` and `/oauth2/revoke` refuse native
  tokens, revoked rows included. Provider 1.6.10's revoked-token branch would
  otherwise delete every refresh token for the user and client. The A2
  ownership check also covers a revoked token from **another** client sent
  with the native `client_id`.

If the session key is stolen too, the attacker becomes a second holder of the
same grant. Whichever party renews second presents a superseded token. Within
30 s that is a harmless 409; after that the grant is revoked, ending both
copies. The attacker gains no more than the device already had.

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
- **KV `list`** on a node without TC-731 can reveal sibling key names outside
  the granted prefix. Production nodes must run a release that includes
  TC-731.
- **SQL on unfixed nodes** is unsafe; it is blocked by the
  `TINYCLOUD_SQL_ISOLATED_HOSTS` gate, not by the node.
- **Pinned provider internals.** The interceptors and hooks depend on
  better-auth 1.6.10's request parsing, revocation branch, token row format
  and hook order. `@better-auth/oauth-provider` is pinned exactly, and the
  interceptor tests act as tripwires on upgrade.
