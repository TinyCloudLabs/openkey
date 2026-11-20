---
"@openkey/core": minor
"@openkey/sdk-capacitor": minor
---

Step-up for a framed app on the native Home grant. `@openkey/core` adds `requestStepUp`, `exchangeStepUpCode`, `validateTinyCloudStepUp` and `revokeStepUp`, the step-up types (`TinyCloudStepUp`, `NativeStepUpPermission`, `NativeStepUpRenewal`), the `tinycloud_delegation_stepup_endpoint` discovery field, and renewal handling for `tinycloud_stepups` (renewed, dropped, failed, removed). `validateTinyCloudStepUp` recovers the EIP-191 signer and refuses a response that does not match the Home grant. `@openkey/sdk-capacitor` adds `OpenKeyNative.requestStepUp({ appId, capabilities })`, `revokeStepUp(appId)`, `stepUpRedirectUri` and `NativeSession.stepUps`; stored sessions load unchanged.

While the API doesn't offer step-up, the new methods reject with `UNAVAILABLE` and store nothing.

Details: TC-3569
