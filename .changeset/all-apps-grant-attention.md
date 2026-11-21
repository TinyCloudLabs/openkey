---
"@openkey/capability-review": patch
---

A grant on the whole applications space (an empty path, so every app's data rather than one app's folder) is now marked for attention when it can change or delete, for key-value writes and deletes and for SQL writes. Its row names the breadth: "Read, change and delete data in all your apps" for key-value, "Read, change and delete records in all your apps" for SQL, and "Read data in all your apps" (key-value) or "Read records in all your apps" (SQL) for read-only access. A grant on one app keeps its existing wording and standard severity. Details: TC-3293
