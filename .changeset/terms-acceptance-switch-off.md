---
"@openkey/api": patch
---

OpenKey asks no account to agree to the Terms of Service. `apps/api/src/terms-release.json` sets no version, so no request gets 403 `terms_required`, no token refresh is refused for the Terms and the Terms screen reports that nothing needs acceptance. Acceptances already on record stay.

Details: TC-3766
