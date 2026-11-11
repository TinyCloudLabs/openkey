---
"@openkey/api": minor
"@openkey/web": minor
"@openkey/capability-review": minor
---

Signed approval requests can name one share invitation (`context` with kind `share-invitation`) and no permissions. When the owner prepares the approval, OpenKey generates a new share key id and signs `key.create` and `decrypt` on that one `default/share/<id>` key, until the invitation's acceptance deadline and for at most 24 hours. The signed SIWE names the approval request in its Request ID (`urn:tinycloud:approval-request:<requestId>:<bodyCid>`), so the requester can check the approval is for its own request. Only a key OpenKey holds can approve it. The approval page shows the recipient, the shared item and the acceptance deadline, names the key's actions after the invitation in the summary and the edit view without the key id, and has no expiry picker for invitations.

Details: TC-2234
