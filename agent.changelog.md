# Agent Changelog

Track changes to agent-facing development guidance for OpenKey. Add a concise entry when
`agent.dev.md` or related agent workflow expectations change.

## 2026-10-21

- Added the public personal-record MCP audience and exact delegation callback
  alongside the existing broad service. Release requires the OpenKey API and
  web changes, plus the SDK candidate; reviewer login and actual ChatGPT
  acceptance remain separate gates. No default-branch integration or deployment
  without explicit owner approval.

## 2026-10-15

- MCP scope registration defaults now match discovery. Omitted-scope clients can request
  `tinycloud:mcp` with user consent; explicit client limits and privileged signing scopes
  stay restricted. Existing connectors with a narrower stored allowlist must re-register.
  Added real-provider OAuth regression coverage to the normal API suite.

## 2026-10-13

- `TEE_MODE` fails closed (TC-966). Only `production` (dstack) and an explicit `development`
  (mock, only with `NODE_ENV` unset, `development` or `test`) are accepted; anything else stops the API at startup.
  `docker-compose.prod.yml` hardcodes `production`. `bun test` gets `TEE_MODE=development` from
  the committed `.env.test`; tests that need the mock outside the repository root must set it
  themselves.

## 2026-10-12

- Sealed-key derivation is frozen (TC-964): `@phala/dstack-sdk` is pinned to exactly `0.5.7` and
  ignored by Dependabot, and a known-answer test runs in the new `dstack key-derivation guard`
  check and the Docker build. Agents never edit its known answers to make it pass.

## 2026-10-03

- Agents never bump a major version (TC-615). Changesets are `minor` or `patch`; a maintainer
  approves a major with an empty `approve-major-release: <package>` commit, enforced by the
  `Major release guard` PR check. Manual Release no longer offers `major`.

## 2026-08-14

- Added the OpenKey-owned Share device authorization contract and public cross-repository smoke.
  Agents changing it must preserve one-time consumption, ten-minute transaction expiry, rate
  limits, device-secret plus PKCE binding, end-to-end encryption to the CLI relay key, and the
  existing delegation approval path. Relay-side encryption of plaintext is not sufficient.

## 2026-05-17

- Added initial agent development notes covering project context, related repositories, build and
  testing expectations, debugging guidance, and additional repo-specific operating context. Tracked
  in TC-1389.
