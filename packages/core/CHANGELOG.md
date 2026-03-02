# @openkey/core

## 0.7.1

### Patch Changes

- b87511e: Fix workspace:\* dependencies leaking to npm — resolve to concrete versions before publish

## 0.7.0

### Minor Changes

- bfa5806: Extract shared PKCE, OAuth URL building, token exchange, and error handling into @openkey/core. Refactor @openkey/sdk and @openkey/sdk-react-native to use @openkey/core instead of duplicated internal implementations. No public API changes to existing SDKs.
