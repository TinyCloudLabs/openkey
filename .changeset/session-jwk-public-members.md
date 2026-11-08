---
"@openkey/api": patch
---

`/api/delegate`, `/api/delegate/prepare`, `/api/delegate/complete` and `/api/delegate/authorize-sign-prepare` use, store and return only the public members of the session JWK a caller sends (`kty`, `crv`, `x` and `kid` for an OKP key). Other members are dropped; requests that include them are still accepted. Requests bound to a device transaction or an approval request keep their existing exact key check.

Each request to these routes also logs one `delegate_session_jwk` line with the route and whether the JWK had a private member (`private_members`), and nothing else from the request.
