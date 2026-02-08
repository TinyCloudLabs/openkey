# @openkey/sdk

## 0.3.0

### Minor Changes

- 2b5a9d6: Add cookieless passkey authentication for iframe embed mode. Proxy endpoints replace cookie-based challenge storage with token-based flow, and bearer plugin enables session persistence without third-party cookies.

## 0.2.1

### Patch Changes

- 5ccc896: Fix iframe modal sizing and update to light theme: remove 700px height cap, use scrollHeight for accurate resize reporting, match modal card background to embed content, remove dark mode overrides

## 0.2.0

### Minor Changes

- a61310d: Add iframe modal as default UI mode, replacing popups.
  - Add `IframeModal` with responsive layout (centered card on desktop, bottom sheet on mobile)
  - Add `WalletPicker` component for parent-side wallet discovery delegation
  - Add `mode` config (`'iframe' | 'popup' | 'redirect'`) with per-operation override
  - Auto-fallback to popup when iframe is blocked by CSP
  - Add embed widget routes (`/widget/embed/connect`, `/widget/embed/sign`, `/widget/embed/sign-typed-data`)
  - Remove `usePopup` config option

## 0.1.0

### Minor Changes

- 6bec495: Fix external wallet linking and signing flow
  - Fix package.json exports map (ESM → index.mjs, CJS → index.js)
  - Add EIP-6963 wallet discovery to link-wallet widget for wallet selection
  - Navigate back to connect page after linking so auth resolves with keyType
  - Use eth_requestAccounts in findWalletProvider to authorize in app context
  - External keys now route signing directly to the user's wallet instead of OpenKey popup

## 0.0.2

### Patch Changes

- afd48ad: Add comprehensive README documentation with usage examples, API reference, and integration guides for ethers.js and TinyCloud.
