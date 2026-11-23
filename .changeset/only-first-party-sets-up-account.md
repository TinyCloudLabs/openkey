---
"@openkey/api": patch
---

Setting up an owner's account on the node as a side effect of a signature is limited to TinyCloud's own apps and to approvals the owner gives on OpenKey's own pages. An app from another site that asks for a signature gets the signature and nothing else. An account's setup records which of these asked, and the background retry picks up only setups that a first-party app or an owner approval started. The prepare reply for a link that will not set the account up says so with a new `spaceSetup.plan` value, `no-setup`.

Details: TC-4115
