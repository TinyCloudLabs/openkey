---
"@openkey/web": patch
---

The embedded sign-in sheet says "That passkey couldn't be used here. Try another passkey or choose Continue with email." when its passkey prompt ends with no passkey used: no passkey matched, the browser refused the prompt in that frame, or the person dismissed it. On the new-account step, which has no "Continue with email" button, it says "That passkey couldn't be used here. Try another passkey or choose Use a different email." Every other passkey error shows its own message.

Details: TC-3901
