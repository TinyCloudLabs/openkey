---
"@openkey/web": patch
---

The approval for a feed connect step now says what the grant does. The three grants it requests (SQL read, write and schema on the feed registry database and on the feed card databases, and change notifications on those databases) read as "Set up and use the agent list in your Feed", "Set up and use cards and answers in your Feed" and "Get notified of changes in your TinyCloud One Feed", where they read as generic database rows. `schema` is the ability to create and edit tables, so the rows say "set up". A row is recognized only for the exact service, space, path and verb set on the signer's own applications space; any other path, verb set, owner or service keeps the generic rows. TC-3126.
