---
"@openkey/capability-review": patch
---

A request that only reads the app list and the space list in your TinyCloud account (`get` or `list` on the `applications/` and `spaces/` registries of your own account space) is summarised as "See your apps and spaces". Its Advanced details line is "Read-only account lists: Reads the list of apps you've installed and the list of your spaces. Nothing can be changed.", exposed as `accountListsReadOnlyDetails`. A capabilities read may sit beside the lists. Any other account grant (a write verb, account SQL, the setup status, delegations) or an unknown owner keeps "Manage your TinyCloud account" or "Manage a TinyCloud account".

Details: TC-3711
