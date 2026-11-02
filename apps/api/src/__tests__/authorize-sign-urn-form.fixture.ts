// Captured from the unmodified /authorize-sign at base da9e736 (TC-1783), same request, fixed key
// 0x0123…cdef, fixed clock. These literals are the "before": the signed bytes, the signature, and the
// response in the old reporting form. Do not regenerate them from the code under test.
export const FIXTURE = {
  "preparedSiwe": "listen.tinycloud.xyz wants you to sign in with your Ethereum account:\n0xFCAd0B19bB29D4674531d6f115237E16AfCE377c\n\nI further authorize the stated URI to perform the following actions on my behalf: (1) 'tinycloud.capabilities': 'read' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/capabilities'. (2) 'tinycloud.duckdb': 'admin', 'describe', 'execute', 'export', 'import', 'read', 'write' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/duckdb'. (3) 'tinycloud.hooks': 'list', 'register', 'subscribe', 'unregister' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/hooks'. (4) 'tinycloud.kv': 'del', 'get', 'list', 'metadata', 'put' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/kv'. (5) 'tinycloud.kv': 'del', 'get', 'list', 'metadata', 'put' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/kv/secrets/'. (6) 'tinycloud.sql': 'admin', 'export', 'read', 'schema', 'write' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/sql'. (7) 'tinycloud.encryption': 'decrypt', 'network.create' for 'urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default'. (8) 'tinycloud.encryption': 'decrypt', 'key.create' for 'urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/qa/'.\n\nURI: did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP#z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP\nVersion: 1\nChain ID: 1\nNonce: OqpK0NYydv9D9jOkO\nIssued At: 2026-10-26T12:00:00.000Z\nExpiration Time: 2026-10-26T13:00:00.000Z\nResources:\n- urn:recap:eyJhdHQiOnsidGlueWNsb3VkOnBraDplaXAxNTU6MToweEZDQWQwQjE5YkIyOUQ0Njc0NTMxZDZmMTE1MjM3RTE2QWZDRTM3N2M6ZGVmYXVsdC9jYXBhYmlsaXRpZXMiOnsidGlueWNsb3VkLmNhcGFiaWxpdGllcy9yZWFkIjpbe31dfSwidGlueWNsb3VkOnBraDplaXAxNTU6MToweEZDQWQwQjE5YkIyOUQ0Njc0NTMxZDZmMTE1MjM3RTE2QWZDRTM3N2M6ZGVmYXVsdC9kdWNrZGIiOnsidGlueWNsb3VkLmR1Y2tkYi9hZG1pbiI6W3t9XSwidGlueWNsb3VkLmR1Y2tkYi9kZXNjcmliZSI6W3t9XSwidGlueWNsb3VkLmR1Y2tkYi9leGVjdXRlIjpbe31dLCJ0aW55Y2xvdWQuZHVja2RiL2V4cG9ydCI6W3t9XSwidGlueWNsb3VkLmR1Y2tkYi9pbXBvcnQiOlt7fV0sInRpbnljbG91ZC5kdWNrZGIvcmVhZCI6W3t9XSwidGlueWNsb3VkLmR1Y2tkYi93cml0ZSI6W3t9XX0sInRpbnljbG91ZDpwa2g6ZWlwMTU1OjE6MHhGQ0FkMEIxOWJCMjlENDY3NDUzMWQ2ZjExNTIzN0UxNkFmQ0UzNzdjOmRlZmF1bHQvaG9va3MiOnsidGlueWNsb3VkLmhvb2tzL2xpc3QiOlt7fV0sInRpbnljbG91ZC5ob29rcy9yZWdpc3RlciI6W3t9XSwidGlueWNsb3VkLmhvb2tzL3N1YnNjcmliZSI6W3t9XSwidGlueWNsb3VkLmhvb2tzL3VucmVnaXN0ZXIiOlt7fV19LCJ0aW55Y2xvdWQ6cGtoOmVpcDE1NToxOjB4RkNBZDBCMTliQjI5RDQ2NzQ1MzFkNmYxMTUyMzdFMTZBZkNFMzc3YzpkZWZhdWx0L2t2Ijp7InRpbnljbG91ZC5rdi9kZWwiOlt7fV0sInRpbnljbG91ZC5rdi9nZXQiOlt7fV0sInRpbnljbG91ZC5rdi9saXN0Ijpbe31dLCJ0aW55Y2xvdWQua3YvbWV0YWRhdGEiOlt7fV0sInRpbnljbG91ZC5rdi9wdXQiOlt7fV19LCJ0aW55Y2xvdWQ6cGtoOmVpcDE1NToxOjB4RkNBZDBCMTliQjI5RDQ2NzQ1MzFkNmYxMTUyMzdFMTZBZkNFMzc3YzpkZWZhdWx0L2t2L3NlY3JldHMvIjp7InRpbnljbG91ZC5rdi9kZWwiOlt7fV0sInRpbnljbG91ZC5rdi9nZXQiOlt7fV0sInRpbnljbG91ZC5rdi9saXN0Ijpbe31dLCJ0aW55Y2xvdWQua3YvbWV0YWRhdGEiOlt7fV0sInRpbnljbG91ZC5rdi9wdXQiOlt7fV19LCJ0aW55Y2xvdWQ6cGtoOmVpcDE1NToxOjB4RkNBZDBCMTliQjI5RDQ2NzQ1MzFkNmYxMTUyMzdFMTZBZkNFMzc3YzpkZWZhdWx0L3NxbCI6eyJ0aW55Y2xvdWQuc3FsL2FkbWluIjpbe31dLCJ0aW55Y2xvdWQuc3FsL2V4cG9ydCI6W3t9XSwidGlueWNsb3VkLnNxbC9yZWFkIjpbe31dLCJ0aW55Y2xvdWQuc3FsL3NjaGVtYSI6W3t9XSwidGlueWNsb3VkLnNxbC93cml0ZSI6W3t9XX0sInVybjp0aW55Y2xvdWQ6ZW5jcnlwdGlvbjpkaWQ6cGtoOmVpcDE1NToxOjB4RkNBZDBCMTliQjI5RDQ2NzQ1MzFkNmYxMTUyMzdFMTZBZkNFMzc3YzpkZWZhdWx0Ijp7InRpbnljbG91ZC5lbmNyeXB0aW9uL2RlY3J5cHQiOlt7fV0sInRpbnljbG91ZC5lbmNyeXB0aW9uL25ldHdvcmsuY3JlYXRlIjpbe31dfSwidXJuOnRpbnljbG91ZDplbmNyeXB0aW9uOmRpZDpwa2g6ZWlwMTU1OjE6MHhGQ0FkMEIxOWJCMjlENDY3NDUzMWQ2ZjExNTIzN0UxNkFmQ0UzNzdjOmRlZmF1bHQvcWEvIjp7InRpbnljbG91ZC5lbmNyeXB0aW9uL2RlY3J5cHQiOlt7fV0sInRpbnljbG91ZC5lbmNyeXB0aW9uL2tleS5jcmVhdGUiOlt7fV19fSwicHJmIjpbXX0",
  "signedMessage": "listen.tinycloud.xyz wants you to sign in with your Ethereum account:\n0xFCAd0B19bB29D4674531d6f115237E16AfCE377c\n\nI further authorize the stated URI to perform the following actions on my behalf: (1) 'tinycloud.capabilities': 'read' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/capabilities'. (2) 'tinycloud.duckdb': 'admin', 'describe', 'execute', 'export', 'import', 'read', 'write' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/duckdb'. (3) 'tinycloud.hooks': 'list', 'register', 'subscribe', 'unregister' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/hooks'. (4) 'tinycloud.kv': 'del', 'get', 'list', 'metadata', 'put' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/kv'. (5) 'tinycloud.kv': 'del', 'get', 'list', 'metadata', 'put' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/kv/secrets/'. (6) 'tinycloud.sql': 'admin', 'export', 'read', 'schema', 'write' for 'tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/sql'. (7) 'tinycloud.encryption': 'decrypt', 'network.create' for 'urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default'. (8) 'tinycloud.encryption': 'decrypt', 'key.create' for 'urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/qa/'.\n\nURI: did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP#z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP\nVersion: 1\nChain ID: 1\nNonce: OqpK0NYydv9D9jOkO\nIssued At: 2026-10-26T12:00:00.000Z\nExpiration Time: 2026-10-26T13:00:00.000Z\nResources:\n- urn:recap:eyJhdHQiOnsidGlueWNsb3VkOnBraDplaXAxNTU6MToweEZDQWQwQjE5YkIyOUQ0Njc0NTMxZDZmMTE1MjM3RTE2QWZDRTM3N2M6ZGVmYXVsdC9jYXBhYmlsaXRpZXMiOnsidGlueWNsb3VkLmNhcGFiaWxpdGllcy9yZWFkIjpbe31dfSwidGlueWNsb3VkOnBraDplaXAxNTU6MToweEZDQWQwQjE5YkIyOUQ0Njc0NTMxZDZmMTE1MjM3RTE2QWZDRTM3N2M6ZGVmYXVsdC9kdWNrZGIiOnsidGlueWNsb3VkLmR1Y2tkYi9hZG1pbiI6W3t9XSwidGlueWNsb3VkLmR1Y2tkYi9kZXNjcmliZSI6W3t9XSwidGlueWNsb3VkLmR1Y2tkYi9leGVjdXRlIjpbe31dLCJ0aW55Y2xvdWQuZHVja2RiL2V4cG9ydCI6W3t9XSwidGlueWNsb3VkLmR1Y2tkYi9pbXBvcnQiOlt7fV0sInRpbnljbG91ZC5kdWNrZGIvcmVhZCI6W3t9XSwidGlueWNsb3VkLmR1Y2tkYi93cml0ZSI6W3t9XX0sInRpbnljbG91ZDpwa2g6ZWlwMTU1OjE6MHhGQ0FkMEIxOWJCMjlENDY3NDUzMWQ2ZjExNTIzN0UxNkFmQ0UzNzdjOmRlZmF1bHQvaG9va3MiOnsidGlueWNsb3VkLmhvb2tzL2xpc3QiOlt7fV0sInRpbnljbG91ZC5ob29rcy9yZWdpc3RlciI6W3t9XSwidGlueWNsb3VkLmhvb2tzL3N1YnNjcmliZSI6W3t9XSwidGlueWNsb3VkLmhvb2tzL3VucmVnaXN0ZXIiOlt7fV19LCJ0aW55Y2xvdWQ6cGtoOmVpcDE1NToxOjB4RkNBZDBCMTliQjI5RDQ2NzQ1MzFkNmYxMTUyMzdFMTZBZkNFMzc3YzpkZWZhdWx0L2t2Ijp7InRpbnljbG91ZC5rdi9kZWwiOlt7fV0sInRpbnljbG91ZC5rdi9nZXQiOlt7fV0sInRpbnljbG91ZC5rdi9saXN0Ijpbe31dLCJ0aW55Y2xvdWQua3YvbWV0YWRhdGEiOlt7fV0sInRpbnljbG91ZC5rdi9wdXQiOlt7fV19LCJ0aW55Y2xvdWQ6cGtoOmVpcDE1NToxOjB4RkNBZDBCMTliQjI5RDQ2NzQ1MzFkNmYxMTUyMzdFMTZBZkNFMzc3YzpkZWZhdWx0L2t2L3NlY3JldHMvIjp7InRpbnljbG91ZC5rdi9kZWwiOlt7fV0sInRpbnljbG91ZC5rdi9nZXQiOlt7fV0sInRpbnljbG91ZC5rdi9saXN0Ijpbe31dLCJ0aW55Y2xvdWQua3YvbWV0YWRhdGEiOlt7fV0sInRpbnljbG91ZC5rdi9wdXQiOlt7fV19LCJ0aW55Y2xvdWQ6cGtoOmVpcDE1NToxOjB4RkNBZDBCMTliQjI5RDQ2NzQ1MzFkNmYxMTUyMzdFMTZBZkNFMzc3YzpkZWZhdWx0L3NxbCI6eyJ0aW55Y2xvdWQuc3FsL2FkbWluIjpbe31dLCJ0aW55Y2xvdWQuc3FsL2V4cG9ydCI6W3t9XSwidGlueWNsb3VkLnNxbC9yZWFkIjpbe31dLCJ0aW55Y2xvdWQuc3FsL3NjaGVtYSI6W3t9XSwidGlueWNsb3VkLnNxbC93cml0ZSI6W3t9XX0sInVybjp0aW55Y2xvdWQ6ZW5jcnlwdGlvbjpkaWQ6cGtoOmVpcDE1NToxOjB4RkNBZDBCMTliQjI5RDQ2NzQ1MzFkNmYxMTUyMzdFMTZBZkNFMzc3YzpkZWZhdWx0Ijp7InRpbnljbG91ZC5lbmNyeXB0aW9uL2RlY3J5cHQiOlt7fV0sInRpbnljbG91ZC5lbmNyeXB0aW9uL25ldHdvcmsuY3JlYXRlIjpbe31dfSwidXJuOnRpbnljbG91ZDplbmNyeXB0aW9uOmRpZDpwa2g6ZWlwMTU1OjE6MHhGQ0FkMEIxOWJCMjlENDY3NDUzMWQ2ZjExNTIzN0UxNkFmQ0UzNzdjOmRlZmF1bHQvcWEvIjp7InRpbnljbG91ZC5lbmNyeXB0aW9uL2RlY3J5cHQiOlt7fV0sInRpbnljbG91ZC5lbmNyeXB0aW9uL2tleS5jcmVhdGUiOlt7fV19fSwicHJmIjpbXX0",
  "signature": "0xceb1283cd5fea81d789a5495c3cf84e1ce6e175ae1f8f58152ad54d8da63327a3440a441644b9b97e6bda62081dc612870c650d08036d6c6a260af9aff0da9651c",
  "digest": "0x0fa222d2d36168c336a8b8ae73122bbab6288ee42491bcf6fef9edaee3628209",
  "previewSelectedActionKeys": [
    "tinycloud.capabilities\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.capabilities/read",
    "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/admin",
    "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/describe",
    "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/execute",
    "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/export",
    "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/import",
    "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/read",
    "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/write",
    "tinycloud.hooks\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.hooks/list",
    "tinycloud.hooks\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.hooks/register",
    "tinycloud.hooks\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.hooks/subscribe",
    "tinycloud.hooks\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.hooks/unregister",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/del",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/get",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/list",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/metadata",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/put",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/del",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/get",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/list",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/metadata",
    "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/put",
    "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/admin",
    "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/export",
    "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/read",
    "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/schema",
    "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/write",
    "tinycloud.encryption\u0000encryption\u0000urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000tinycloud.encryption/decrypt",
    "tinycloud.encryption\u0000encryption\u0000urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000tinycloud.encryption/network.create",
    "tinycloud.encryption\u0000encryption\u0000urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/qa/\u0000tinycloud.encryption/decrypt",
    "tinycloud.encryption\u0000encryption\u0000urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/qa/\u0000tinycloud.encryption/key.create"
  ],
  "previewPermissions": [
    {
      "service": "tinycloud.capabilities",
      "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
      "path": "",
      "actions": [
        "tinycloud.capabilities/read"
      ]
    },
    {
      "service": "tinycloud.duckdb",
      "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
      "path": "",
      "actions": [
        "tinycloud.duckdb/admin",
        "tinycloud.duckdb/describe",
        "tinycloud.duckdb/execute",
        "tinycloud.duckdb/export",
        "tinycloud.duckdb/import",
        "tinycloud.duckdb/read",
        "tinycloud.duckdb/write"
      ]
    },
    {
      "service": "tinycloud.hooks",
      "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
      "path": "",
      "actions": [
        "tinycloud.hooks/list",
        "tinycloud.hooks/register",
        "tinycloud.hooks/subscribe",
        "tinycloud.hooks/unregister"
      ]
    },
    {
      "service": "tinycloud.kv",
      "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
      "path": "",
      "actions": [
        "tinycloud.kv/del",
        "tinycloud.kv/get",
        "tinycloud.kv/list",
        "tinycloud.kv/metadata",
        "tinycloud.kv/put"
      ]
    },
    {
      "service": "tinycloud.kv",
      "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
      "path": "secrets/",
      "actions": [
        "tinycloud.kv/del",
        "tinycloud.kv/get",
        "tinycloud.kv/list",
        "tinycloud.kv/metadata",
        "tinycloud.kv/put"
      ]
    },
    {
      "service": "tinycloud.sql",
      "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
      "path": "",
      "actions": [
        "tinycloud.sql/admin",
        "tinycloud.sql/export",
        "tinycloud.sql/read",
        "tinycloud.sql/schema",
        "tinycloud.sql/write"
      ]
    },
    {
      "service": "tinycloud.encryption",
      "space": "encryption",
      "path": "urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
      "actions": [
        "tinycloud.encryption/decrypt",
        "tinycloud.encryption/network.create"
      ]
    },
    {
      "service": "tinycloud.encryption",
      "space": "encryption",
      "path": "urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/qa/",
      "actions": [
        "tinycloud.encryption/decrypt",
        "tinycloud.encryption/key.create"
      ]
    }
  ],
  "oldResponse": {
    "selectedActionKeys": [
      "tinycloud.capabilities\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.capabilities/read",
      "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/admin",
      "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/describe",
      "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/execute",
      "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/export",
      "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/import",
      "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/read",
      "tinycloud.duckdb\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.duckdb/write",
      "tinycloud.hooks\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.hooks/list",
      "tinycloud.hooks\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.hooks/register",
      "tinycloud.hooks\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.hooks/subscribe",
      "tinycloud.hooks\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.hooks/unregister",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/del",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/get",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/list",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/metadata",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.kv/put",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/del",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/get",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/list",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/metadata",
      "tinycloud.kv\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000secrets/\u0000tinycloud.kv/put",
      "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/admin",
      "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/export",
      "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/read",
      "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/schema",
      "tinycloud.sql\u0000tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000\u0000tinycloud.sql/write",
      "tinycloud.encryption\u0000encryption\u0000urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000tinycloud.encryption/decrypt",
      "tinycloud.encryption\u0000encryption\u0000urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default\u0000tinycloud.encryption/network.create",
      "tinycloud.encryption\u0000encryption\u0000urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/qa/\u0000tinycloud.encryption/decrypt",
      "tinycloud.encryption\u0000encryption\u0000urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/qa/\u0000tinycloud.encryption/key.create"
    ],
    "permissions": [
      {
        "service": "tinycloud.capabilities",
        "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
        "path": "",
        "actions": [
          "tinycloud.capabilities/read"
        ]
      },
      {
        "service": "tinycloud.duckdb",
        "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
        "path": "",
        "actions": [
          "tinycloud.duckdb/admin",
          "tinycloud.duckdb/describe",
          "tinycloud.duckdb/execute",
          "tinycloud.duckdb/export",
          "tinycloud.duckdb/import",
          "tinycloud.duckdb/read",
          "tinycloud.duckdb/write"
        ]
      },
      {
        "service": "tinycloud.hooks",
        "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
        "path": "",
        "actions": [
          "tinycloud.hooks/list",
          "tinycloud.hooks/register",
          "tinycloud.hooks/subscribe",
          "tinycloud.hooks/unregister"
        ]
      },
      {
        "service": "tinycloud.kv",
        "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
        "path": "",
        "actions": [
          "tinycloud.kv/del",
          "tinycloud.kv/get",
          "tinycloud.kv/list",
          "tinycloud.kv/metadata",
          "tinycloud.kv/put"
        ]
      },
      {
        "service": "tinycloud.kv",
        "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
        "path": "secrets/",
        "actions": [
          "tinycloud.kv/del",
          "tinycloud.kv/get",
          "tinycloud.kv/list",
          "tinycloud.kv/metadata",
          "tinycloud.kv/put"
        ]
      },
      {
        "service": "tinycloud.sql",
        "space": "tinycloud:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
        "path": "",
        "actions": [
          "tinycloud.sql/admin",
          "tinycloud.sql/export",
          "tinycloud.sql/read",
          "tinycloud.sql/schema",
          "tinycloud.sql/write"
        ]
      },
      {
        "service": "tinycloud.encryption",
        "space": "encryption",
        "path": "urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default",
        "actions": [
          "tinycloud.encryption/decrypt",
          "tinycloud.encryption/network.create"
        ]
      },
      {
        "service": "tinycloud.encryption",
        "space": "encryption",
        "path": "urn:tinycloud:encryption:did:pkh:eip155:1:0xFCAd0B19bB29D4674531d6f115237E16AfCE377c:default/qa/",
        "actions": [
          "tinycloud.encryption/decrypt",
          "tinycloud.encryption/key.create"
        ]
      }
    ]
  }
} as const;
