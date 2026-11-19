---
"@openkey/sdk": minor
---

Signing requests the server refuses now reject with their own error code instead of `UNKNOWN`: `APP_KEY_GRANT_REFUSED` (the request asks for an encryption key this website can't be granted), `KEY_DELETE_NOT_GRANTABLE` or `INVALID_SIWE_RECAP`. The codes are exported as the `OpenKeyRefusalCode` type, and the messages are unchanged. Apps that check `code === 'UNKNOWN'` for these refusals need to check the new codes instead.

Details: TC-2928
