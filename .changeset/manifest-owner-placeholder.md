---
"@openkey/api": patch
---

The sign-in manifest check accepts a published manifest that writes the owner's identifier as `{owner}` in a permission path, and resolves it with the signer's own identifier, so apps whose manifest names the owner can show as served by the verified origin.

A manifest with literal braces in a permission path, or with `{owner}` outside a permission path, binds as unsigned and loses the origin-bound label.

Details: TC-3714
