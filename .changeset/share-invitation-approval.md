---
"@openkey/api": minor
"@openkey/web": minor
---

Signed approval requests can name one share invitation (`context` with kind `share-invitation`) and no permissions. When the owner prepares the approval, OpenKey generates a new share key id and signs `key.create` and `decrypt` on that one `default/share/<id>` key, until the invitation's acceptance deadline and for at most 24 hours. The signed SIWE names the approval request in its Request ID (`urn:tinycloud:approval-request:<requestId>:<bodyCid>`), so the requester can check the approval is for its own request. Only a key OpenKey holds can approve it. A file invitation's access may last past its acceptance deadline, up to the policy-root lifetime (`POLICY_ROOT_MAX_LIFETIME_SECONDS` from `@tinycloud/share-envelope`, 31 days) after the request was sent; a longer one is refused before approval, never shortened; a session invitation's access equals it. The approval page shows the recipient, the shared item, the acceptance deadline and, for a file, the access expiry, each with its duration from now, names the key's actions after the invitation in the summary and the edit view without the key id, and has no expiry picker for invitations.

Details: TC-2234
