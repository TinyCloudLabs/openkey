---
"@openkey/web": patch
---

A read-only request to list which apps and links can reach your data (`tinycloud.delegation` with `list` or `status`) on your own `applications` space is labelled "See which apps and links can reach your data", a standard permission, rather than "Unrecognized delegation target". Any other verb, any other space and another user's space are classified as before. Details: TC-2113
