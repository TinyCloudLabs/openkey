# Product

## Register

product

## Users

OpenKey has two primary authenticated surfaces:

- Individual account holders using the personal OpenKey Account for keys, connected apps, and ownership transfers.
- Organization admins and members using the OpenKey Console to manage apps, server credentials, managed accounts, and webhooks for a tenant.

Users arrive with a live session and need a task-focused interface that keeps tenant boundaries explicit, reduces accidental cross-tenant actions, and exposes only real API-backed controls.

## Product Purpose

OpenKey exists to let users manage passkey-authenticated Ethereum key workflows and tenant-managed account infrastructure without raw API calls.

The personal account surface supports identity, security, and user-owned custody actions. The organizational console supports tenant setup and day-to-day operations: creating organizations, configuring apps, issuing one-time credentials, inspecting managed accounts, and reviewing webhook delivery state.

Success means an admin can complete first-run activation from the browser, a member can read the same organizational state without mutation controls, and sensitive one-time secrets are handled safely.

## Brand Personality

Clear, operational, and trustworthy.

The interface should feel like a serious control plane: calm under load, precise in language, and explicit about what is configured versus what is enforced. It should not feel decorative, speculative, or overloaded with dashboard theater.

## Anti-references

- Consumer SaaS dashboards with decorative gradients, fake metrics, or noisy hero sections.
- Personal-finance style visual excess or marketing-style empty states in the console.
- Hidden tenant boundaries, ambiguous roles, or controls that imply capability the API does not grant.
- Generic admin panels that treat one-time secrets like durable values.

## Design Principles

1. Show real state only. Every screen should reflect the current API-backed organization state, not placeholders or invented progress.
2. Keep tenant boundaries obvious. Personal account actions and organizational console actions must stay visually and behaviorally distinct.
3. Make privileged actions explicit. Admin-only mutations should be clear, while member views stay useful but read-only.
4. Treat sensitive data as ephemeral. One-time secrets must be revealed intentionally and never persisted in browser storage.
5. Prefer earned familiarity. Standard product UI patterns are good when they reduce confusion and support fast operational work.

## Accessibility & Inclusion

- Target WCAG AA contrast.
- Support keyboard navigation, focus visibility, reduced motion, and clear disabled/error states.
- Preserve readable density on small screens without hidden controls or horizontal overflow.
- Avoid relying on color alone to convey tenant role, status, or secret boundary messages.
