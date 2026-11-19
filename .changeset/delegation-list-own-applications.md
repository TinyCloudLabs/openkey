---
"@openkey/web": patch
---

A read-only request to list the delegations of your account (`tinycloud.delegation` with `list` or `status`) on your own `account` or `applications` space is labelled "See which apps and links can reach your data, and the names of what each can reach", a standard permission, and described as "See who has access to your data, what it reaches (by name) and when it ends. Keys and contents aren't shown." On the `applications` space the request was labelled "Unrecognized delegation target"; on the `account` space it was "Connected access and sharing" ("Manage your TinyCloud account" as the sentence). Any other verb, any other space and another user's space are classified as before. Details: TC-2113
