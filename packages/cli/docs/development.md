# OpenKey CLI — Development Guide

## Architecture

The CLI is at `packages/cli/` in the OpenKey monorepo. It authenticates users via OAuth 2.1 PKCE by opening a browser and receiving the callback on a local HTTP server.

### Package Dependencies
- `@openkey/core` (workspace) — PKCE, OAuth URL building, token exchange, errors
- `commander` — CLI argument parsing
- `open` — cross-platform browser opening

### Source Structure
```
packages/cli/src/
├── cli.ts              # Entry point, commander setup, global options
├── auth.ts             # OAuth login flow (local HTTP server + browser open)
├── credentials.ts      # Token persistence (~/.openkey/credentials.json)
├── api.ts              # Authenticated fetch helper, auto-refresh
└── commands/
    ├── login.ts        # openkey login [--no-browser]
    ├── logout.ts       # openkey logout
    ├── whoami.ts       # openkey whoami
    ├── keys.ts         # openkey keys
    ├── sign.ts         # openkey sign <message> [--key-id <id>]
    └── token.ts        # openkey token (prints access token for piping)
```

### Build
- Built with tsup (ESM only, shebang banner)
- Binary: `packages/cli/dist/cli.js`
- `bin` field in package.json: `{ "openkey": "./dist/cli.js" }`

## Key Concepts

### OAuth PKCE Login Flow
1. Generate PKCE verifier + challenge + state via `@openkey/core`
2. Start ephemeral HTTP server on `localhost:{random_port}`
3. Build authorization URL via `buildAuthorizationUrl()` from core
4. Open browser (or print URL with `--no-browser`)
5. Server receives `GET /callback?code=...&state=...`
6. Validate state, exchange code for tokens via `exchangeAuthorizationCode()`
7. Save tokens to `~/.openkey/credentials.json`, shut down server

### Credential Storage
- Location: `~/.openkey/credentials.json`
- Permissions: `0600` (owner read/write only)
- Keyed by host URL (supports multiple OpenKey instances)
- Stores: `{ tokens: AuthTokens, storedAt: ISO string }`
- Auto-refresh: commands call `getValidTokens()` which refreshes expired tokens

### Global CLI Options
- `--host <url>` — OpenKey server (default: `https://openkey.so`)
- `--client-id <id>` — OAuth client ID (required for most commands)

## Adding a New Command

1. Create `src/commands/mycommand.ts`:
```typescript
import { authenticatedFetch } from '../api';

export async function myCommand(options: { host: string; clientId: string }) {
  const res = await authenticatedFetch(options.host, options.clientId, '/api/my-endpoint');
  if (!res.ok) throw new Error(`Failed: ${res.status}`);
  const data = await res.json();
  console.log(data);
}
```

2. Register in `src/cli.ts`:
```typescript
import { myCommand } from './commands/mycommand';

program
  .command('mycommand')
  .description('Does something')
  .action(async () => {
    const { host, clientId } = program.opts();
    await myCommand({ host, clientId });
  });
```

3. Build: `bun run --filter '@openkey/cli' build`
4. Test: `node packages/cli/dist/cli.js mycommand --client-id <id>`

## OpenKey API Endpoints (used by CLI)

| Command | Endpoint | Auth |
|---------|----------|------|
| login | `POST /api/auth/oauth2/token` | PKCE code exchange |
| logout | `POST /api/auth/revoke` | Bearer token |
| whoami | `GET /api/auth/userinfo` | Bearer token |
| keys | `GET /api/keys` | Bearer token |
| sign | `POST /api/keys/:keyId/sign` | Bearer token |
| token | (local only) | reads stored credentials |

## @openkey/core Functions Used

- `generateCodeVerifier()` — sync, returns base64url string
- `generateCodeChallenge(verifier, sha256?)` — async, SHA-256 hash
- `generateState()` — sync, returns base64url string
- `buildAuthorizationUrl(opts)` — builds full OAuth authorize URL
- `exchangeAuthorizationCode(opts)` — POSTs to token endpoint, returns `AuthTokens`
- `refreshAccessToken(opts)` — refresh flow, returns `AuthTokens`
- `OpenKeyError` — error class with typed `code` field

## Testing

```bash
# Build
bun run --filter '@openkey/cli' build

# Verify binary
node packages/cli/dist/cli.js --help

# Smoke test against local dev server
node packages/cli/dist/cli.js login --no-browser --host http://localhost:3001 --client-id <id>
```

## Conventions
- All commands that need auth use `getValidTokens()` or `authenticatedFetch()` from `api.ts`
- Errors are `OpenKeyError` instances with typed codes
- `token` command writes to stdout without newline (for piping)
- No graceful fallbacks — let errors surface clearly
