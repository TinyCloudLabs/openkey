---
"@openkey/sdk": patch
---

Fix sequential signMessage requests failing with USER_CANCELLED

When a dapp called signMessage twice in sequence (e.g., vault unlock deriving two keys), the second request was rejected with USER_CANCELLED. The openkey:close message from the first sign widget iframe was being received by the second modal's message handler. Added event.source checks to IframeModal and popup message handlers so each only processes messages from its own iframe/popup window.
