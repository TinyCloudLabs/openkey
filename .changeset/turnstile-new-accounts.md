---
"@openkey/api": minor
"@openkey/web": minor
---

New accounts created by email one-time code sign-up pass a Cloudflare Turnstile check before the account is created. `POST /api/auth/sign-up/email-otp` requires a `turnstileToken` for new accounts and returns `503` with `code: "REGISTRATION_PAUSED"` when the check is not configured. Sign-in for existing accounts is unchanged. Clients that create accounts through the API send the token from the widget. The web sign-up screens show the widget and a retry message when the check fails or does not load.

The QA exemption reads its patterns from `TEST_ACCOUNT_REGISTRY_JSON`. A QA-eligible pattern must be anchored with `^...$` (no top-level `|`) and must end in `@` followed by a literal domain and `$` (two or more `a-z0-9-` labels joined by `\.`, with no wildcard, class, group or quantifier in the domain part). The domain must not be gmail.com, outlook.com, hotmail.com, yahoo.com, icloud.com, proton.me or protonmail.com, or a subdomain of one. Otherwise the registry is refused at load, `config_invalid` is logged with a `reason` (`unanchored_pattern`, `unqualified_domain_pattern` or `public_mail_domain_pattern`), and the exemption stays off. Each QA-exempt account creation also logs `auth_email_signup_qa_daily_count` with the UTC `day` and the running `count` for that day.

Details: TC-1632
