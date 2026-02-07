---
"@openkey/sdk": minor
---

Fix external wallet linking and signing flow

- Fix package.json exports map (ESM → index.mjs, CJS → index.js)
- Add EIP-6963 wallet discovery to link-wallet widget for wallet selection
- Navigate back to connect page after linking so auth resolves with keyType
- Use eth_requestAccounts in findWalletProvider to authorize in app context
- External keys now route signing directly to the user's wallet instead of OpenKey popup
