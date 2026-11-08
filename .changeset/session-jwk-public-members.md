---
"@openkey/api": patch
---

`/api/delegate`, `/api/delegate/prepare`, `/api/delegate/complete` and `/api/delegate/authorize-sign-prepare` use, store and return only the public members of the session JWK a caller sends (`kty`, `crv`, `x` and `kid` for an OKP key). Other members are dropped; requests that include them are still accepted. Requests bound to a device transaction or an approval request keep their existing exact key check.

Each request to these routes also logs one `delegate_session_jwk` line with the route and whether the JWK had a private member (`private_members`), and nothing else from the request.

A session JWK that is not a plain object, has an unknown `kty`, or has a non-string `kty`, `crv`, `x`, `y`, `n`, `e` or `kid` is treated as missing (the route's existing required-field error); a request naming a device transaction is refused by the device check instead, as before. On `POST /api/delegate` and `/complete`, an `approvalRequestId` of `null`, `false` or `""` without a consent preview context is refused like any other approval request.

A delegation bound to an approval request refuses a session JWK with any private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`, `oth`), not only `d`, with its existing binding error.
