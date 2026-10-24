---
"@openkey/api": patch
"@openkey/web": patch
---

`/api/delegate/authorize-sign-prepare` admits encryption key grants under `apps/<app_id>/` when the request comes from the app's own https origin, the app id is bound to that origin's host (reversed host labels equal the id or are followed by a dot), the manifest fetched from that origin matches the declared digest, its `keys` block declares every requested key or prefix and ability, the owner is the signing key's own `did:pkh` on the `default` network, and the message carries an `Expiration Time`. Any other `apps/` grant is refused with a reason. The preview and sign steps read the admitted grants from the context and sign them byte for byte. The app keys of a request are approved with the rest of it or removed as a unit: a selection that keeps one app-key action and drops another answers 400 `app_key_group_partial`. In the approval view the app keys have one checkbox, and the other checkboxes are disabled while it is ticked. Details: TC-1777
