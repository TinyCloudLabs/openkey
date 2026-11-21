---
"@openkey/api": patch
---

The sign-in manifest check accepts a published manifest that writes the owner's identifier as `{owner}` in a permission path, and resolves it with the signer's own identifier, so apps whose manifest names the owner can show as served by the verified origin.

Details: TC-3714
