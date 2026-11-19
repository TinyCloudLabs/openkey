---
"@openkey/api": minor
---

Add `POST /api/internal/org-owner-check` for OpenCredentials (TC-128). The caller authenticates with an owner-check JWS signed by the pinned issuer DID key (EdDSA, `typ` `org-owner-check+jwt`, claims `iss`, `aud`, `purpose`, `keyId`, `account`, `jti`, `iat`, `exp`; lifetime at most 60 s). The answer is `{"owner":true}` only when `account` is a managed, non-archived personal key of the user holding the accepted, unrevoked OWNER grant on that non-archived org key; external keys, unknown keys and null grantees answer `false`. The route is read-only, has no body, sends no CORS headers, and answers 404 unless `ORG_KEY_CUSTODY_ENABLED` is `true`. The issuer DID resolver and strict JWS helpers moved into `services/issuer-jws.ts` and are shared with the registration intent verifier, with no behaviour change there.
