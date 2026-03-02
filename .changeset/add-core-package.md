---
"@openkey/core": minor
"@openkey/sdk": patch
"@openkey/sdk-react-native": patch
---

Extract shared PKCE, OAuth URL building, token exchange, and error handling into @openkey/core. Refactor @openkey/sdk and @openkey/sdk-react-native to use @openkey/core instead of duplicated internal implementations. No public API changes to existing SDKs.
