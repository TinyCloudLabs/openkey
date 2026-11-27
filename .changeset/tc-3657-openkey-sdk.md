---
"@openkey/sdk": minor
---

New `OpenKey.authorizeTinyCloudSetup(request?)` sets up TinyCloud for a new person from an outside app. Call it when the app's TinyCloud sign-in throws `AccountSetupRequiredError`. It opens OpenKey's setup window and resolves to `{ status: "published" | "already-current" | "declined" | "unavailable"; subject? }`. `request.requestingApp.name` and `request.requestingApp.manifest` appear on the screen as the app's own claim and don't change what is published. It pairs with `tcw.handleAccountSetupRequired` in `@tinycloud/web-sdk`.

Details: TC-3657
