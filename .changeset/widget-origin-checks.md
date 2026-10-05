---
"@openkey/web": patch
---

The embedded connect widget no longer posts the OpenKey session token to the embedding page (TC-688). The connect and sign-typed-data widgets (popup and embedded) now require an exact `?origin=`, never post to `*`, and accept messages only from that origin and the opening window (TC-690). The embedded sign-typed-data widget ignores a `sessionToken` in the request.

What breaks: opening these widgets without an `origin` query parameter (the SDK always sends one) leaves them unable to reply.
