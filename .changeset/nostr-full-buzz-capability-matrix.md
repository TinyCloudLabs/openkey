---
"@openkey/sdk": minor
---

Expand `OpenKeyNostr` to the complete Buzz web capability matrix. `connect()`
accepts a requested capability set (`kinds`, `operations`, `relayUrl`) so a
client's full working set can be approved in one consent card. `signEvent()`
supports the full Buzz event-kind allowlist with per-kind payload validation
and destination binding for relay/Blossom/HTTP auth kinds, and accepts an
optional `relayUrl` consent hint. New custody crypto methods -
`nip44Encrypt` (encrypt-to-self), `nip44Decrypt`, `nip59Wrap`, and
`nip59Unwrap` - perform NIP-44 v2 and NIP-59 gift-wrap operations inside the
custody boundary without ever exposing the secret key or a conversation key.
The widget wire protocol stays at version 1; the new message types are
additive.
