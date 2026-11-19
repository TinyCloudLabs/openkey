---
"@openkey/api": patch
---

Restrict cookie-session requests to managed-key signing routes to account-facing browser origins. The admin console host is no longer allowlisted for those requests. `POST /api/delegate/sign` applies this origin check to cookie sessions only; its OAuth bearer flow is unchanged. Credentialed CORS and Better Auth trusted origins are unchanged, so the console keeps its own API calls and sign-in.
