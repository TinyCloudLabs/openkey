---
"@openkey/sdk-capacitor": minor
"@openkey/core": patch
---

`loginMethod: 'apple'` is accepted by native sign-in (TC-1233): `@openkey/core` and `@openkey/sdk-capacitor` send `login_method=apple` in the PAR request, and OpenKey's sign-in sheet then opens Sign in with Apple in that same system sheet, without an app entitlement. A `loginHint` is still allowed only with `email`. `NativeLoginMethod` is now exported. Offer Apple only when `GET /api/auth/providers` lists it.
