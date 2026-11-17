---
"@openkey/capability-review": patch
---

Decrypt on several exact shared files (`share/<id>` keys on the owner's default network) is now one summary row that counts them, "Open {n} shared files", instead of a single "Open this shared file" row that read as one file. One file still reads "Open this shared file". `shareFilesDecryptStatement(count)` returns the row text. The row stays Sensitive. Details: TC-3204
