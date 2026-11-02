---
"@openkey/capability-review": patch
---

The consent review now builds its summary rows in one place (`buildSummaryStatements`), and the Sensitive header counts exactly the rows marked Sensitive (`sensitiveSummaryCount`, `sensitiveRowsCallout`) instead of counting grants. The own-key folder rows ("Create your own encryption keys in share/", "Decrypt data locked with your keys in share/") are flagged `codeSpans` so the path shows in code style, not between raw backquotes.

The owner's decrypt on their `default/share/` folder reads "Open all your shared files, including ones you share later." (wording Sam approved on 10-31, ask/openkey-388-share-approval), and an owner's decrypt on one exact share key reads "Open this shared file"; every other key row keeps its sentence. Details: TC-2242, TC-1424
