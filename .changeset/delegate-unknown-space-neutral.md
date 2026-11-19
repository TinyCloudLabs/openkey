---
"@openkey/web": patch
---

When OpenKey has no new answer about the requested space after an approval (`spaceReady` unknown, for example because the node already held the delegation), the approval screen now says so neutrally and shows it in a plain grey box instead of an amber warning. Wording only; approvals and `spaceReady` are unchanged (TC-2933).
