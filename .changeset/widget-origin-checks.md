---
"@openkey/web": patch
---

The embedded connect widget no longer posts the OpenKey session token to the embedding page (TC-688). The connect and sign-typed-data widgets (popup and embedded) now require an exact `?origin=`, never post to `*`, and accept messages only from that origin and the opening window (TC-690). The embedded sign and sign-typed-data widgets ignore a `sessionToken` in the request. The sign-out widgets (popup and embedded) ignore a request `sessionToken` and revoke the session OpenKey holds itself.

What breaks: opening the connect or sign-typed-data widgets without an `origin` query parameter (the SDK always sends one) leaves them unable to reply. A page that injected a session into the embedded sign widget through the request message no longer can.
