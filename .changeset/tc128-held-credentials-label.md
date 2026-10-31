---
"@openkey/capability-review": patch
---

The consent review names one exact request: the signer's own `credentials` space, path `v1/held/`, with exactly the abilities `get`, `list`, `put` and `del` on `tinycloud.kv`. The summary reads "Manage your verified email credentials" and Advanced details title it "Verified email credentials". The grant keeps family `unknown`, so its severity stays Sensitive, and it does not enter the "reach secrets or decryption" count. Any other space, owner, chain, path spelling, action set or service keeps the generic wording. Display text only: the signed request is unchanged. Details: TC-128
