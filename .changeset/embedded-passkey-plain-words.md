---
"@openkey/web": patch
---

The embedded sign-in sheet says "That passkey couldn't be used here. Try another passkey or choose Continue with email." when its passkey prompt ends with no passkey used: no passkey matched, the browser refused the prompt in that frame, or the person dismissed it. Every other passkey error shows its own message.

Details: TC-3901
