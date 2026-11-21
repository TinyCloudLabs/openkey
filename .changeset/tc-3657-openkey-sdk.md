---
"@openkey/sdk": minor
---

TC-3657: new `OpenKey.authorizeTinyCloudSetup(request?)` method for outside-app one-tap TinyCloud setup. The outside app's error handler catches `AccountSetupRequiredError` from its TinyCloud sign-in and calls this; OpenKey opens the consent in a top-level popup (always, regardless of `opts.mode`), the owner approves, and OpenKey's server signs and publishes the owner's registry location record. The outside app never sees the signed record; the method returns `{ status: "published" | "already-current" | "declined" | "unavailable"; subject? }`.

`request.requestingApp.name` and `request.requestingApp.manifest` are DISPLAYED CLAIMS only. OpenKey never uses them to shape the signed record, the setup ticket, the rate limit, or any grant. The requesting app's origin on the consent screen comes from the browser's `postMessage` `event.origin`; the SDK does not accept an `origin` field in the request.

Pairs with the SDK-side helper `tcw.handleAccountSetupRequired` in `@tinycloud/web-sdk` (TC-3547 PR #1113). Full flow: app sign-in throws → `tcw.handleAccountSetupRequired` → `openkey.authorizeTinyCloudSetup` → popup consent → sign + publish → app retries sign-in → succeeds.

Details: TC-3657.
