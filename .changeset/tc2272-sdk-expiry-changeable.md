---
"@openkey/sdk": minor
---

`authorizeTinyCloud` takes an optional `expiryChangeable: true` and forwards it to the sign widget (managed and external keys), only when it is literally `true`. Set it only when your app accepts a signed message whose `Expiration Time` differs from the SIWE you sent (shorter or longer) and reads the expiry from the returned `signedMessage`: OpenKey then shows "Approval expires … (Change)" and signs the time the user picks. Without it the widget shows no expiry control and your expiry is signed. Details: TC-2272
