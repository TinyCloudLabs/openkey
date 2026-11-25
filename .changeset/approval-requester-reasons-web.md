---
"@openkey/web": patch
---

The approval screen shows one line under "OpenKey can’t confirm who made this link." when the link's signer is a listed requester and its request is outside what that requester may ask for: longer access, a service, an action, data, a space, renewal, a kind of request it does not send, or a request OpenKey cannot read. The requester stays "Not verified". An approval request also shows the key its access goes to under the requester line, as "Access goes to" with the first 6 and last 4 characters of the key and the whole key on opening it.

Details: TC-4400
