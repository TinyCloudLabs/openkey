---
"@openkey/api": patch
---

OpenKey classifies every form of an app-key resource as an app key on every route. An encryption resource written as a space path, `<space>/encryption/apps/…` (or `<space>/tinycloud.encryption/apps/…`), in any space and with any capitalisation of `apps`, is read as an app key from the text of a message and from its parsed entries, in the same way as the key URN, and is refused on the same routes. Paths outside `apps/`, kv paths under `apps/`, and the space-level resource with an empty path are unchanged.
