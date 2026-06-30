# @openkey/sdk-react-native

## 0.8.8

### Patch Changes

- f478606: Allow embedded OpenKey registration popups to escape the SDK iframe sandbox.
- Updated dependencies [f478606]
  - @openkey/core@0.8.8

## 0.8.7

### Patch Changes

- 2d363b1: Update package license metadata and bundled license text to the TinyCloud Open Source License.

## 0.8.5

### Patch Changes

- fe323ae: Update TypeScript to v6, zod to v4, commander to v14, adapter-cloudflare to v7
- Updated dependencies [fe323ae]
  - @openkey/core@0.8.5

## 0.7.1

### Patch Changes

- b87511e: Fix workspace:\* dependencies leaking to npm — resolve to concrete versions before publish
- Updated dependencies [b87511e]
  - @openkey/core@0.7.1

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
