---
"@openkey/web": patch
---

Approve on the sign popups (message, typed data, Nostr grant) and on a key's sign form sends nothing until the passkey offer for what is being signed has arrived. The button is busy while the offer is on its way, and the arrival of the offer approves nothing by itself. A failed offer fetch shows "Couldn't get your passkey ready. Try again."; the next tap fetches the offer again and sends nothing until it lands. An offer that says no passkey is needed signs without an assertion.

Details: TC-3698
