---
"@openkey/api": patch
"@openkey/web": patch
---

The approval screen shows an Expires row reading "Doesn't expire. It doesn't end by itself." for a sign-in message with no `Expiration Time`. `/api/keys/:id/sign` refuses (400 `invalid_siwe_message`) a `0x` hex sign-in message that starts with a byte-order mark or has a byte that isn't UTF-8. Binary hex that holds no sign-in message signs.

Details: TC-3826
