# Agent Changelog

Track changes to agent-facing development guidance for OpenKey. Add a concise entry when
`agent.dev.md` or related agent workflow expectations change.

## 2026-08-14

- Added the OpenKey-owned Share device authorization contract and public cross-repository smoke.
  Agents changing it must preserve one-time consumption, ten-minute transaction expiry, rate
  limits, device-secret plus PKCE binding, encrypted relay storage, and the existing delegation
  approval path.

## 2026-05-17

- Added initial agent development notes covering project context, related repositories, build and
  testing expectations, debugging guidance, and additional repo-specific operating context. Tracked
  in TC-1389.
