---
"@openkey/capability-review": patch
---

The consent review now builds its summary rows in one place (`buildSummaryStatements`), and the Sensitive header counts exactly the rows marked Sensitive (`sensitiveSummaryCount`, `sensitiveRowsCallout`) instead of counting grants. The own-key folder rows ("Create your own encryption keys in share/", "Decrypt data locked with your keys in share/") are flagged `codeSpans` so the path shows in code style, not between raw backquotes.
