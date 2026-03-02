# @openkey/sdk-react-native

## 0.7.0

### Patch Changes

- bfa5806: Extract shared PKCE, OAuth URL building, token exchange, and error handling into @openkey/core. Refactor @openkey/sdk and @openkey/sdk-react-native to use @openkey/core instead of duplicated internal implementations. No public API changes to existing SDKs.
- Updated dependencies [bfa5806]
  - @openkey/core@0.7.0

## 0.0.5

### Patch Changes

- Restore full OAuth scopes (openid email keys offline_access) for muse-api OpenKey authentication

## 0.0.4

### Patch Changes

- Reduce OAuth scopes to 'openid' only to fix login on servers that don't yet support email/keys/offline_access scopes

## 0.0.3

### Patch Changes

- ed86b1b: Add EGPL license to npm package and include LICENSE.md in published files

## 0.0.2

### Patch Changes

- 58ef40a: Add React Native SDK with OAuth 2.1 + PKCE authentication flow
