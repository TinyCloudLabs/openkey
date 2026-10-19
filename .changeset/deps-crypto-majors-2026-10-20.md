---
"@openkey/tee": patch
---

Dependency update: `@noble/curves` 1.9.7 → 2.4.0 and `@scure/base` 1.2.6 → 2.4.0 (crypto majors). Nostr key custody (`nostr.ts`) now imports `@noble/curves/secp256k1.js` and `@noble/curves/utils.js` (v2 exports only `.js` subpaths) and uses `schnorr.utils.randomSecretKey`. Keys, npubs and BIP-340 signatures are unchanged; no stored data is affected.
