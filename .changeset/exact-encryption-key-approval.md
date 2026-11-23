---
"@openkey/capability-review": minor
---

The approval for a grant that unlocks and creates one exact encryption key names the key. Its heading reads "Create and use one encryption key: {name}" and its sentence reads "{site} could create the encryption key named {name} and unlock the items encrypted with it, for as long as this approval lasts. It can't use any other key." A grant on a folder keeps its folder wording. `elevatedExactKey` gives the key's name when the grant ends without a trailing slash and the path is a valid key, and `elevatedCard` takes it as a fifth argument.

Details: TC-4073
