---
"@openkey/api": patch
---

`/api/delegate` and `/api/delegate/prepare` accept a raw encryption entry for the `share/` folder of the signer's own encryption network (`urn:tinycloud:encryption:<owner>:<network>/share/`, decrypt only), next to a bare network. The CLI's `--manifest builtin:share-publishing` sign-in sends exactly that entry and was refused before consent with "names an invalid encryption network". Every other path after the network name, any other action, and a network the signer does not own are still refused. Details: TC-2349
