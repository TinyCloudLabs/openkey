---
"@openkey/api": minor
"@openkey/web": minor
---

A website may now ask to decrypt, or create keys, on your encryption network or on keys outside its own app area (TC-2927). The approval shows an extra screen for each such permission, marked Sensitive, with "Reject this permission" and "Allow this permission" and neither chosen for you. A permission you reject is left out and the rest of the request is still approved; a request that cannot be split is approved or cancelled whole. The server refuses to sign an extra permission you did not explicitly allow. This replaces the earlier refusal of these requests (`app_key_grant_refused` for any site not on a first-party list), and the list of first-party sites is removed. A request for one exact share key (`share/<id>`) is still refused for every site, ours included, because the id is chosen by the app and you cannot judge it; the share/ prefix and the whole network are not exact keys.
