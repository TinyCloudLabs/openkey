---
"@openkey/api": minor
"@openkey/web": minor
---

The approval screen shows "Approval expires: 7d (Change)", defaulting to the expiry the app requested. Change opens a picker (1 hr, 24 hr, 7d, 30d) and a box that takes a time like 5600s, 90m, 40d or 1y (units s, m, h, d, w, y; a year is 365 days). There is no upper limit; a time over one year shows "That's a long time. You can revoke it any time." The time the user picks is written into the signed message's `Expiration Time` by `/api/delegate/authorize-sign-preview` (new optional `expirationTime`, an exact ISO-8601 UTC time after now and after the request's Issued At), sealed in the preview approval, and signed by `/api/delegate/authorize-sign` exactly as previewed; an external signer signs the previewed bytes as before. It is on the website popup, the embedded frame and the prepared CLI handoff. Signed CLI approval requests, device approvals and the plain `/delegate` link keep the lifetime their request fixes; the exact-byte path for requests without a protocol version signs the app's own bytes. Details: TC-2272
