---
"@openkey/api": patch
---

`https://tinycloud.one`, the Home app's new site, is a first-party origin for encryption grants outside `apps/`. A sign-in from it can ask for `decrypt` and `key.create` on the owner's encryption network, as tinycloud.chat and home.tinycloud.xyz already can. The match is the exact origin: `www.tinycloud.one`, other subdomains, other ports, `http://` and other casings are still refused.
