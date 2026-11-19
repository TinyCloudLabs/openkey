---
"@openkey/web": patch
---

The approval view shows the space and the node ID in its summary when a request asks to host a space. In the app popup and iframe, the node is marked as a known TinyCloud node at its configured address or as not confirmed, after the page asks the known nodes for their key for that space; Approve waits for that check. `/delegate` shows the space on the session consent line. The known-node list is checked against the API's trusted bootstrap hosts. The capability review and web lib tests now run in the API tests workflow.

Details: TC-1950
