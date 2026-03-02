---
name: openkey-cli
description: Authenticate with OpenKey, manage keys, and sign messages from the terminal. Use when the user needs to log in to OpenKey, list or manage Ethereum keys, sign messages, or get access tokens from the command line.
---

# OpenKey CLI

## Quick start

```bash
openkey login --client-id <id>           # Sign in (opens browser)
openkey whoami --client-id <id>          # Show current user
openkey keys --client-id <id>            # List your keys
openkey sign "hello" --client-id <id>    # Sign a message
```

## Authentication

```bash
openkey login                    # Open browser for OAuth sign-in
openkey login --no-browser       # Print URL instead (for SSH/headless)
openkey logout                   # Revoke tokens and clear credentials
```

Login opens your browser to OpenKey, authenticates via OAuth 2.1 PKCE, and stores tokens locally. With `--no-browser`, it prints the URL for you to open manually while the local callback server waits.

Credentials are saved to `~/.openkey/credentials.json` (permissions `0600`). Tokens auto-refresh when expired.

## User info

```bash
openkey whoami                   # Show email, keys, account info
```

## Key management

```bash
openkey keys                     # List all keys (address, type, label)
```

## Signing

```bash
openkey sign "hello world"                  # Sign with default key
openkey sign "hello world" --key-id <id>    # Sign with specific key
```

Signs a message using a managed key via OpenKey's TEE. Returns the signature and address.

## Access tokens

```bash
openkey token                    # Print access token to stdout
```

Outputs the current access token with no trailing newline, for piping to other tools:

```bash
curl -H "Authorization: Bearer $(openkey token --client-id <id>)" \
  https://openkey.so/api/keys
```

## Global options

```bash
openkey --host <url>             # OpenKey server (default: https://openkey.so)
openkey --client-id <id>         # OAuth client ID (required)
openkey --version                # Show version
openkey --help                   # Show help
openkey <command> --help         # Show help for a command
```

## Using with a local dev server

```bash
openkey login --host http://localhost:3001 --client-id <id>
openkey whoami --host http://localhost:3001 --client-id <id>
```

Credentials are stored per-host, so you can be logged in to both production and local simultaneously.

## Registering an OAuth client

Before using the CLI, register an OAuth client for it:

```bash
# In the openkey monorepo
bun run oauth:register \
  --name "OpenKey CLI" \
  --type native \
  --redirect-uri "http://127.0.0.1"
```

Use the returned client ID with `--client-id`.

## Example: Full workflow

```bash
# Register a CLI client (one-time setup)
bun run oauth:register --name "My CLI" --type native --redirect-uri "http://127.0.0.1"
# Output: Client ID: ok_abc123

# Log in
openkey login --client-id ok_abc123

# Check identity
openkey whoami --client-id ok_abc123
# Email: sam@example.com
# Address: 0xAbC...dEf

# List keys
openkey keys --client-id ok_abc123
# ck_123  0xAbC...dEf  MANAGED  "default"
# ck_456  0x789...012  EXTERNAL "metamask"

# Sign a message
openkey sign "authorize action" --client-id ok_abc123
# Signature: 0x1a2b3c...
# Address: 0xAbC...dEf

# Use token in scripts
TOKEN=$(openkey token --client-id ok_abc123)
curl -H "Authorization: Bearer $TOKEN" https://openkey.so/api/keys
```

## Example: Headless / SSH environment

```bash
openkey login --no-browser --client-id ok_abc123

# Output:
# Open this URL in your browser to sign in:
#   https://openkey.so/api/auth/oauth2/authorize?client_id=ok_abc123&...
#
# Waiting for callback...

# Open the URL on another machine, authenticate, and the CLI
# receives the callback on its local server.

# Authenticated as sam@example.com
```

## Error codes

| Code | Meaning |
|------|---------|
| `UNAUTHORIZED` | Not logged in or session expired — run `openkey login` |
| `NETWORK_ERROR` | Cannot reach OpenKey server |
| `TIMEOUT` | Login flow timed out waiting for browser callback |
| `STATE_MISMATCH` | CSRF check failed — retry login |
| `UNKNOWN` | Unexpected error |
