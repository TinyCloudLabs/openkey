---
"@openkey/web": patch
---

The sign screens (`/widget/sign` and `/widget/embed/sign`) show what an app says about a plain `signMessage()` request: its name, who the request is for and its reason. The words sit under the verified "Requested by" origin and are marked as unchecked, in these lines: `It calls itself "{name}". OpenKey hasn't checked that name.`, `It says it's asking for "{onBehalfOf}".`, `Its reason: "{reason}"` and one closing line `OpenKey hasn't checked these.` when two or three are shown (`OpenKey hasn't checked this.` for an on-behalf-of or reason alone). Texts are cleaned and length-capped. A name, on-behalf-of or reason that imitates another site or a TinyCloud or OpenKey product, including with lookalike letters from other scripts, is dropped, and so is a name or on-behalf-of that mixes scripts. The signed bytes, the Approve tap and the requests to the API are the same with or without these words, and nothing of the presentation is sent to the signer or the API. The widget's `openkey:ready` message carries `presentation: 1`.

Details: TC-3706
