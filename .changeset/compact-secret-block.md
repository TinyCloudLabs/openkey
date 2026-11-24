---
"@openkey/web": patch
---

A sign face that asks to read secrets shows one row ("Read the secret NAME", "Read secret values" or "Read all your secret values") with the Sensitive mark, one line saying what it covers and a 1 hour | asked-length toggle with the end of the chosen length beside it. A read of one secret has the same row with or without a key request. The end is the Expiration Time of the message that is signed. A secret's name stays on one line. The secrets read by name are listed in a Secrets group under Advanced details. The lifetime sentence, the "marked Sensitive" header and a key creation that comes with a read are not on the main face. A request with a write, a wildcard, a wider path, the scoped prefix, a scoped secret or another account's secrets keeps its own rows.

Details: TC-4226
