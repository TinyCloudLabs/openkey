---
"@openkey/web": patch
---

Standard approval pages refresh an expired or unavailable authorization context once through the normal prepare endpoint, keeping the owner's selected permissions. The five-minute context lifetime and backend validation are unchanged.

Managed-key approval continues automatically. External wallets receive one additional signing prompt for the fresh message; the previous signature is never reused. Expired requests, refused refreshes, a second context failure, or a declined second signature show a plain request-for-a-new-link message instead of continuing approval. Embedded and prepared-handoff flows are unchanged.

The expired state uses the existing confirmation card and key icon, with the requester named when already known. The card sits near the top on narrow screens without unnecessary scrolling.

Details: TC-2505.
