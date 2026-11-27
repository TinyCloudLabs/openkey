---
"@openkey/api": minor
"@openkey/web": minor
"@openkey/db": minor
---

OpenKey can set up TinyCloud for a new person from an outside app. When the app's sign-in finds no TinyCloud account, `OpenKey.authorizeTinyCloudSetup()` opens a setup window on OpenKey's own site. After the person approves, OpenKey publishes the account's location record, with the TinyCloud node taken from its own configuration.

New endpoints: `POST /api/tinycloud-setup/mint-ticket` and `POST /api/tinycloud-setup/publish`. New page: `/widget/tinycloud-setup`, which opens only as its own window. New tables from migration `20261122_0002_tinycloud_setup_tables`.

Setup needs two settings, `TINYCLOUD_DEFAULT_NODE_DID` and `OPENKEY_SETUP_TICKET_SECRET`. Until both are set, the setup endpoints return `503 setup_unavailable`, and the rest of OpenKey runs normally.

Deploy order: run the migration, deploy the API with both settings, then the web app, then publish the SDK.

Details: TC-3657
