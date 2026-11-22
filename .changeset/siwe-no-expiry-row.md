---
"@openkey/api": patch
"@openkey/web": patch
---

The approval screen's Expires row now says "Doesn't expire. It doesn't end by itself." for a sign-in message with no `Expiration Time`, instead of showing no row. `/api/keys/:id/sign` refuses (400 `invalid_siwe_message`) a `0x` hex sign-in message that starts with a byte-order mark or has a byte that is not UTF-8; binary hex that holds no sign-in message still signs. Details: TC-3826
