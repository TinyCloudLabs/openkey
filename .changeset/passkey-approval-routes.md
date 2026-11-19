---
"@openkey/api": minor
---

Approvals ask for the account's passkey as its passkey-for-approvals setting calls for (TC-3442). Signing a message or typed data with a key, granting a Nostr signer, delegating access to an app, signing an app's sign-in, approving a native app, turning on an app's TinyCloud signing, and sharing TinyCloud key management each check the setting in the same request that signs. Where a passkey is needed, the preview response (`/api/delegate/prepare`, `/api/delegate/authorize-sign-preview`, native `prepare`) carries `passkey: { required, challengeToken, options }`, and the other routes offer one at `POST …/passkey`. The approval then sends `passkeyAssertion: { challengeToken, response }`. A missing or wrong assertion is refused with 403 and `code` `passkey_approval_required`, `passkey_approval_invalid` or `passkey_not_step_up_capable`, before anything is signed. Revoking, turning things off and external-wallet flows never ask.

Details: TC-3442
