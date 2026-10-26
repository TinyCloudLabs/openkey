---
"@openkey/api": patch
---

An authorize request for the `tinycloud:mcp` scope on a web sign-in that is 23 days old or older is sent through the provider's login prompt first, so a new MCP connection is approved on a sign-in with more than a week left before the 30-day cap. The request is the same one with `login` added to `prompt`; after the user signs in the provider resumes it on the new session. With `prompt=none` the client gets the provider's own `login_required` error redirect instead (the request reaches the provider without the sign-in's credentials), and no code or consent is created. The scope is the request's, or the client's own when the request names none. Younger sign-ins, other scopes and other clients are unchanged. The sign-in's age is read without renewing it.
