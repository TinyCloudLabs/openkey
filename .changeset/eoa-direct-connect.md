---
"@openkey/sdk": minor
---

Support direct EOA wallet connect in non-OAuth flows. When an EOA wallet is detected (EIP-6963 or window.ethereum), the connect widget shows a muted "or use an external wallet" option below the passkey sign-in button. Selecting it routes back to the SDK's wallet picker, bypassing OpenKey authentication entirely.
