---
"@openkey/web": patch
---

The native consent page's refusal screen, shown when a request is of a kind the page can't show, now says "This request needs a newer version of the app." with "Nothing was allowed. Update the app, then try again." and a "Back to the app" button that denies the request and returns to the app. If that fails, the screen stays with the error and nothing to allow. The step-up screen reads "{app} will be able to read more of your data, on top of what {client} already has." and its undecodable-request line reads "This request can’t be read, so it can’t be allowed."

Details: TC-3569
