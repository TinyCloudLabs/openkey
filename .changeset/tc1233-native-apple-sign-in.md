---
"@openkey/sdk-capacitor": minor
"@openkey/core": patch
"@openkey/api": minor
"@openkey/web": minor
---

Native sign-in accepts `loginMethod: 'apple'` (TC-1233). The SDK and PAR pass `login_method=apple`, and OpenKey's sign-in sheet opens Sign in with Apple in the same system sheet, with no app entitlement. Native social errors are typed and provider-specific: cancelled, failed, `apple_email_required`, account-exists and new-account confirmations, including the Hide My Email notice. Offer Apple only when `GET /api/auth/providers` lists it; that endpoint now answers any origin without credentials so native WebViews can read it. `NativeLoginMethod` is exported from `@openkey/core` and `@openkey/sdk-capacitor`.
