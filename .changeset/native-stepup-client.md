---
"@openkey/core": minor
"@openkey/sdk-capacitor": minor
---

Step-up for a framed app on the native Home grant (TC-3569). `@openkey/core` adds `requestStepUp`, `exchangeStepUpCode`, `validateTinyCloudStepUp` and `revokeStepUp`, the step-up types (`TinyCloudStepUp`, `NativeStepUpPermission`, `NativeStepUpRenewal`), the `tinycloud_delegation_stepup_endpoint` discovery field, and renewal handling for `tinycloud_stepups` (renewed, dropped, failed, removed). `validateTinyCloudStepUp` recovers the EIP-191 signer and refuses a response that does not match the Home grant. `@openkey/sdk-capacitor` adds `OpenKeyNative.requestStepUp({ appId, capabilities })`, `revokeStepUp(appId)`, `stepUpRedirectUri` and `NativeSession.stepUps`; stored sessions load unchanged.

The server side stays off behind `OPENKEY_NATIVE_STEPUP_ENABLED`. When the API does not offer step-up the new methods reject with `UNAVAILABLE` and store nothing.
