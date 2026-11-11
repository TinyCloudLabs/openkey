---
"@openkey/api": minor
"@openkey/web": minor
"@openkey/capability-review": minor
---

Signed approval requests can name one share invitation (`context` with kind `share-invitation`) and no permissions. When the owner prepares the approval, OpenKey generates a new share key id and signs `key.create` and `decrypt` on that one `default/share/<id>` key, until the invitation's acceptance deadline and for at most 24 hours. The approval page shows the recipient, the shared item and the acceptance deadline, and the key row reads "Create an encryption key for this invitation only" without the key id.

Details: TC-2234
