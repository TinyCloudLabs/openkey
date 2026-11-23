---
"@openkey/api": patch
---

The secrets list, write and delete leave TinyChat's bot-history key and its scope alone. The key is `secrets/scoped/tinychat-bot-history/bot-history`, and any key in that scope is treated the same, in any spelling the SDK reads as that scope, such as `Tinychat-Bot-History`. The list omits them, and a write or a delete of one is refused with "This key is reserved". The key and scope are copied from `@tinycloud/sdk-services` 3.14.0-beta.17, and a test pins them.

Details: TC-3970
