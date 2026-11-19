---
"@openkey/api": patch
---

`/api/delegate`, `/api/delegate/prepare`, `/api/delegate/complete` and `/api/delegate/authorize-sign-prepare` refuse a session JWK that includes any private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`, `oth`) with 400 `private_jwk_refused`.

What breaks: clients that send the full session key pair instead of its public key get 400 on these routes. Ship this only after the SDKs that send the public key alone are released and adopted.
