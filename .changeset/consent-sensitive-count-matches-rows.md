---
"@openkey/capability-review": patch
---

The consent review now builds its summary rows in one place (`buildSummaryStatements`), and the Sensitive header counts exactly the rows marked Sensitive (`sensitiveSummaryCount`, `sensitiveRowsCallout`) instead of counting grants. Generic own-key folder rows are flagged `codeSpans` so their paths show in code style, not between raw backquotes.

The owner's create on `default/share/` reads "Create keys for files you share" (Naomi's TC-1424 wording/test ruling, folded in ahead of #398's rebase). Decrypt on that folder stays "Open all your shared files, including ones you share later." (wording Sam approved on 10-31, ask/openkey-388-share-approval), and decrypt on one exact share key stays "Open this shared file"; every other key row keeps its sentence. Details: TC-2242, TC-1424

Recognized owner key-creation rows are no longer marked Sensitive; decrypt rows remain Sensitive. This changes only statement-level presentation, not grant classification, selected abilities, or server authorization.
