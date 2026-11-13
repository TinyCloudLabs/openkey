---
"@openkey/sdk": minor
---

A signing request the server definitely refuses now rejects with its own error code: `APP_KEY_GRANT_REFUSED` (the request asks for an encryption key this website may not be granted), `KEY_DELETE_NOT_GRANTABLE` or `INVALID_SIWE_RECAP`, exported as the `OpenKeyRefusalCode` type. The message is unchanged. Apps that matched these refusals as `code === 'UNKNOWN'` must match the new codes instead. Details: TC-2928
