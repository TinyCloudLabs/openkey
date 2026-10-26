# Token status check for resource servers

A hosted resource, such as the TinyCloud MCP server, can ask OpenKey whether an access token issued for it is still active. OpenKey's provider endpoint `/oauth2/introspect` only answers for the client a token was issued to, and JWT access tokens carry no state there, so this is a separate endpoint.

## Request

`POST /api/oauth/resource/introspect`, `application/x-www-form-urlencoded`, RFC 7662 shaped:

- `token`: the JWT access token. At most 8 KiB.
- `token_type_hint`: accepted and ignored.
- Client authentication, one of: HTTP Basic (`client_secret_basic`), or the form fields `client_id` and `client_secret` (`client_secret_post`). Not both.

## Response

- `200 {"active": true, "scope", "client_id", "sub", "aud", "exp", "iat", "iss", "token_type": "Bearer"}`. Only these fields. `aud` is the intersection of the token's own `aud` with this server's allowed resources, an array if the token's `aud` is an array and a string if it is a string. If the intersection is empty the answer is `active: false`; a non-empty one may be a subset of what the token carries.
- `200 {"active": false}` for any token that is not active, whatever the reason: not a JWT, bad signature, wrong issuer, expired or not yet valid, no `iat`, an audience this server may not check, the issuing client disabled or deleted, the user's consent for the issuing client withdrawn or not holding the token's scope, the consent was granted again after the token was issued, or the OpenKey sign-in that authorized the token has ended. A bad token is never a 400 or 500.
- `401 {"error": "invalid_client", ...}`: missing or wrong credentials, a public client, a disabled client, or a client that is not a registered resource server.
- `429 {"error": "too_many_requests"}` with `Retry-After`: rate limited. The limit is per authenticated client: 3000 requests per minute unless the client's registration sets another (1 to 100000); about 20 failed authentications per minute per source address.
- `503 {"error": "temporarily_unavailable"}`: OpenKey could not answer.

429 and 503 are not answers about the token. A caller may keep serving a token it was told is active, at most until that token's `exp`; it must not serve a token it has not seen active.

All responses are `Cache-Control: no-store`. A caller may cache `active: true` for a short fixed time, which bounds how long a withdrawn token stays usable.

A token is active only while the OpenKey sign-in that authorized it is active; a successful refresh extends that sign-in up to 30 days after it began.

A token is not active if it is older than the user's current consent. Disconnecting deletes the consent and connecting again creates a new one, so a token issued before the new consent stays inactive after the user reconnects: it is `active: false` when the token's `iat` is earlier than the consent's creation time. Both are compared in whole seconds (consent times have second precision), so a token issued in the same second as the consent is active, which is the token of the sign-in that created it. A consent time OpenKey cannot read ends the token.

## Registering a resource server

A resource server is a confidential client (`public: false`, `type: web`, `client_secret_basic`) whose `metadata` holds `tinycloudResourceServer.allowedResources`, the canonical resource URLs (token audiences) it may check, and optionally `rateLimitPerMinute`. It may hold several resources, for example `https://mcp.tinycloud.xyz/mcp` and `https://mcp.tinycloud.xyz/chatgpt/mcp`. Each must be an audience OpenKey issues tokens for (`OAUTH_VALID_AUDIENCES`, plus the built-in ones); registration names any that is not.

Run the "Register Resource Server" workflow (`scripts/ci-register-resource-server.ts`) with the name, the allowed resources (comma-separated; locally, repeat `--allowed-resource <url>`), optionally `rate_limit_per_minute`, and the RSA public key (2048 bits or more) of whoever will hold the secret. The client secret is generated in the job and never printed; only its RSA-OAEP (SHA-256) ciphertext is, and the key holder decrypts it:

```sh
echo "$CIPHERTEXT" | base64 -d | openssl pkeyutl -decrypt -inkey private.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
```

The secret cannot be shown again. To rotate it, disable the client and register again. Registering a name that already exists changes nothing, so give every resource at the first run, or once the last audience is deployed.

## Revocation at `/oauth2/revoke`

A token's own revocation at `/oauth2/revoke` does not change its status here.
