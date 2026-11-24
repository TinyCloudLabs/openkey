---
"@openkey/sdk": patch
---

The SDK modal puts its handle and close button in a strip above the embedded OpenKey frame, and nothing of the modal overlaps the frame. A sign page inside the modal can use a passkey sign-in as the approval for the request it just signed in for, so the person taps one passkey instead of two.

Details: TC-4234
