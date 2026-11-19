---
"@openkey/api": minor
"@openkey/web": minor
"@openkey/db": minor
---

Required Terms acceptance (TC-3232). With a release set in `apps/api/src/terms-release.json` (version, text SHA-256, optional "What changed" line, `privacyChanged`, `requiredVersion` for editorial fixes), an account must agree to the Terms of Service and acknowledge the Privacy Policy before it can use OpenKey. As shipped the file sets no version, so nothing changes until a reviewed change turns it on; a file that does not fit the shape stops the API at boot.

- New append-only `terms_acceptance` record (userId, documentId, version, textSha256, acceptedAt, surface, appVersion), one row per account and version.
- `GET /api/account/terms` and `POST /api/account/terms/accept {version}`; only the current version is accepted (409 `terms_version_mismatch` otherwise).
- Until the account accepts: session routes answer 403 `terms_required` with `terms_url`; OAuth authorize sends the browser to `/auth/terms` (post-login step) and consent/continue are refused; native prepare/approve and device approve are refused; token refresh, native renew and userinfo are refused without rotating or revoking anything. Native deny and revoke stay open.
- App-review accounts are recorded as accepting the current version at start and when provisioned.
- Web: the `/auth/terms` screen (one "Agree and continue" button; "Don't agree and sign out" is a plain sign-out), shown inline after sign-in and sign-up before the passkey offer, and after any `terms_required` refusal, returning to the page or app the user was headed to.
