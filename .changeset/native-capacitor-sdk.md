---
'@openkey/sdk-capacitor': minor
---

Add the Capacitor 8 native sign-in SDK with iOS and Android secure storage, TinyCloud delegation verification, renewal, revocation, and a secure TinyCloud session storage adapter. First release starts at 0.1.0.

Transient revoke failures now leave only a secure pending-revoke key and refresh token for automatic retry. Terminal renewal outcomes clear the session and best-effort revoke rotated grants; failed new sign-in attempts preserve an existing session. Equivalent normalized permission subsets share one renewal flight.
