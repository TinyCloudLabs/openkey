---
"@openkey/api": minor
---

Users without a passkey can now delete their account using a fresh deletion email code (`purpose: "delete_account"` on the email step-up endpoints). Users with a passkey still need a fresh passkey. After a deletion commits, each stored Apple refresh token is revoked with the client ID that issued it.

Add `POST /api/webhooks/apple` for Apple server-to-server notifications. It is not found unless Apple sign-in is enabled and `APPLE_WEBHOOK_AUDIENCE` is set.
- Each notification is verified against Apple's signing keys and applied once per `jti`.
- `consent-revoked` and `account-deleted` end the user's sessions, native grants and OAuth tokens, and keep the account, its keys and the Apple link.
- Email events mark an Apple relay address as undeliverable.

Locked accounts are now refused everywhere they hold access: session lookup (cookie and bearer), OAuth token grants and access-token answers, native grant renewal, and the signing routes.

`GET /api/account` returns `user.emailUndeliverable`. Unlinking is refused when no passkey remains and the email is unverified or undeliverable.

Adds migration `20261110_0001_apple_notifications`.
