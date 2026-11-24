---
"@openkey/web": minor
---

A one-tap approval request (`/a/…`) signed by a listed TinyCloud One key is shown as requested by TinyCloud One: "Requested by", "Returned to", "Sent to" and the last page's "return to TinyCloud One". Any other signer is shown as not verified, with no requester name. The built-in list is empty until One's key is set; a deployment lists its key in `VITE_TINYCLOUD_ONE_REQUESTER_DIDS` (Ed25519 `did:key`).

An approval for exactly one named secret (read `vault/secrets/NAME` in the owner's secrets space) and decrypt on the owner's encryption network shows the rows "Read the secret NAME" and "Decrypt your data" instead of "Read secret values" and "Decrypt protected data". On a one-tap request it also gets the heading "TinyCloud One wants to use one secret" (signed by One's key) or "A request to use one secret" (any other signer), the line "Review it, choose how long, then approve." and a note under the decrypt row that it covers all encrypted data until each secret has its own key. Any other request keeps its heading and rows.

Details: TC-3695
