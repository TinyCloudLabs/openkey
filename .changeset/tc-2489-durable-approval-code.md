---
"@openkey/api": minor
"@openkey/web": minor
---

Durable approval links show a short, one-time confirmation code after approval, with an instruction to tell the requesting agent or paste the code into the chat. Requesters can collect that code for the same saved request through the signed result-discovery endpoint, then use the existing encrypted-result verification and acknowledgement flow. Codes expire within five minutes and no later than result retention; acknowledgement invalidates them. Plain-delegation paste, device and prepared-handoff transports are unchanged.

On screens up to 480px wide, durable approval confirmations align near the top with reduced padding instead of full-height vertical centring. Desktop layout is unchanged.

Code-allocation failures emit a structured warning containing request identifiers and a sanitized error class, without logging the approval code or error details. Saved approvals remain collectable without a code.

Details: TC-2489.
