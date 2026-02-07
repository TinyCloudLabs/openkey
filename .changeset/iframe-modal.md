---
"@openkey/sdk": minor
---

Add iframe modal as default UI mode, replacing popups.

- Add `IframeModal` with responsive layout (centered card on desktop, bottom sheet on mobile)
- Add `WalletPicker` component for parent-side wallet discovery delegation
- Add `mode` config (`'iframe' | 'popup' | 'redirect'`) with per-operation override
- Auto-fallback to popup when iframe is blocked by CSP
- Add embed widget routes (`/widget/embed/connect`, `/widget/embed/sign`, `/widget/embed/sign-typed-data`)
- Remove `usePopup` config option
