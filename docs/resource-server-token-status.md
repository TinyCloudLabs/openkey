# Token status check for resource servers

A hosted resource, such as the TinyCloud MCP server, can ask OpenKey whether an access token issued for it is still active. OpenKey's provider endpoint `/oauth2/introspect` only answers for the client a token was issued to, and JWT access tokens carry no state there, so this is a separate endpoint.

## Request

`POST /api/oauth/resource/introspect`, `application/x-www-form-urlencoded`, RFC 7662 shaped:

- `token`: the JWT access token. At most 8 KiB.
- `token_type_hint`: accepted and ignored.
- Client authentication, one of: HTTP Basic (`client_secret_basic`), or the form fields `client_id` and `client_secret` (`client_secret_post`). Not both.

## Response

- `200 {"active": true, "scope", "client_id", "sub", "aud", "exp", "iat", "iss", "token_type": "Bearer"}`. Only these fields. `aud` lists only audiences this server is allowed to check.
- `200 {"active": false}` for any token that is not active, whatever the reason: not a JWT, bad signature, wrong issuer, expired or not yet valid, an audience this server may not check, the issuing client disabled or deleted, the user's consent for the issuing client withdrawn (or narrower than the token's scope), or the user's session gone. A bad token is never a 400 or 500.
- `401 {"error": "invalid_client", ...}`: missing or wrong credentials, a public client, a disabled client, or a client that is not a registered resource server.
- `429 {"error": "too_many_requests"}` with `Retry-After`: rate limited (600 requests per minute per authenticated client; 20 failed authentications per minute per source address).
- `503 {"error": "temporarily_unavailable"}`: OpenKey could not answer. Treat it, and any other non-`200`, as inactive.

All responses are `Cache-Control: no-store`. A caller may cache `active: true` for a short fixed time, which bounds how long a withdrawn token stays usable.

## Registering a resource server

A resource server is a confidential client (`public: false`, `type: web`, `client_secret_basic`) whose `metadata` holds `tinycloudResourceServer.allowedResources`, the canonical resource URLs (token audiences) it may check. Each must be an audience OpenKey issues tokens for (`OAUTH_VALID_AUDIENCES`, plus the MCP default).

Run the "Register Resource Server" workflow (`scripts/ci-register-resource-server.ts`) with the name, the allowed resources, and the RSA public key (2048 bits or more) of whoever will hold the secret. The client secret is generated in the job and never printed; only its RSA-OAEP (SHA-256) ciphertext is, and the key holder decrypts it:

```sh
echo "$CIPHERTEXT" | base64 -d | openssl pkeyutl -decrypt -inkey private.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
```

The secret cannot be shown again. To rotate it, disable the client and register again.

## Not covered yet

A token's own revocation at `/oauth2/revoke` is not reflected: JWT access tokens carry no identifier and OpenKey keeps no revocation list. Reflecting it needs a `jti` claim and a revoked-token table, and is a separate change.
