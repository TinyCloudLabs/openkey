// Side-effect free so `routes/delegate-session.ts` can apply the same allowlist when it signs a device approval.

/**
 * Device-flow scope policy (TC-539). A device approval is phishable: anyone
 * can start a request and send its code to a victim. Requests are therefore
 * limited to an explicit allowlist of data abilities on one ordinary space:
 *
 * - services: `tinycloud.kv` and `tinycloud.capabilities` only, always fully
 *   qualified. `tinycloud.sql` is deferred: Node authorizes SQL descendant
 *   paths but selects the database by the final path segment, so a grant for
 *   `notes` could reach database `private` through `notes/private`;
 * - abilities: KV get/list/metadata/put/del and capabilities read. SQL,
 *   delegation, space, hooks, encryption, secrets, DuckDB, VFS, and wildcard
 *   abilities are rejected;
 * - spaces: one per request; `account` (account registry), `applications`
 *   (application registry) and `secrets` are rejected;
 * - paths: KV grants name an explicit relative path (no whole-space grants,
 *   no `.`/`..` segments, no `secrets/` or `vault/` roots) and no KV path may
 *   cover another (Node grants cover every path beneath a granted path);
 *   capabilities grants are space-wide (empty path);
 * - `tinycloud.capabilities/read` is required: every OpenKey delegation
 *   carries it, so it is never optional at consent.
 */
export const DEVICE_FLOW_ABILITIES: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'tinycloud.kv': ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata', 'tinycloud.kv/put', 'tinycloud.kv/del'],
  'tinycloud.capabilities': ['tinycloud.capabilities/read'],
});
