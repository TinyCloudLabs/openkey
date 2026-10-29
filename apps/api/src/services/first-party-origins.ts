// Sites OpenKey treats as first-party for one purpose (TC-2247): `/api/keys/:keyId/sign`
// signs a message that names encryption `decrypt` or `key.create` outside `apps/` only
// for these origins. Every other site is refused (`encryptionOutsideAppsRefusal`).
//
// The origin is the verified requesting origin of the TC-1486 check: the page origin the
// widget saw on the postMessage, sent as `requestOrigin`. Matching is byte-exact on that
// string, so a different case, port, scheme or trailing text is not first-party.
//
// Each entry says where the app asks for the grant, as `file:line` in the app's own
// repository (the checkouts read on 2026-10-29). Change an entry together with that app.

export const FIRST_PARTY_ENCRYPTION_ORIGINS: ReadonlySet<string> = new Set([
  // tinychat web. tinychat: frontend/src/lib/connectors/encryptionGrant.ts:55-65 (decrypt on the
  // bare network), frontend/src/App.tsx:929 (added to the sign-in manifest),
  // packages/client/src/openkey.ts:51-58 (personal_sign -> openkey.signMessage).
  'https://tinycloud.chat',
  // tinychat desktop (Exo) on macOS and Linux. tinychat: backend/src/cors-origins.ts:2; the
  // SIWE origin guard special-cases it (services/siwe-origin.ts, APP_SHELL_ORIGINS).
  'tauri://localhost',
  // tinychat desktop (Exo) on Windows. tinychat: backend/src/cors-origins.ts:5 and :35.
  'http://tauri.localhost',
  // Share. share: src/share/openkey-session.ts:194 (decrypt and network.create on the owner's
  // network), :73-77 (explicitOpenKeyApproval -> openkey.signMessage).
  'https://share.tinycloud.xyz',
  // Secret Manager. secret-manager: src/lib/tinycloud-manifest.ts:36-41 (decrypt on the default
  // network), src/lib/vault-client.ts:64 and :76 (sign-in), :103-107 (network.create).
  'https://secrets.tinycloud.xyz',
  // Inbox (TC-2230 slice 3, inbox #32). The tailnet-only host that serves the Inbox page under
  // /inbox-pair/; the origin has no path and no port, and it is also the SIWE domain. The one
  // sign-in asks for `decrypt` (inbox: src/authority.ts:37) and `network.create` (src/consent.ts:20)
  // on the owner's `inbox` encryption network (src/authority.ts:29), through
  // OpenKey.signMessage (src/browser.ts:15 mode 'iframe', :105). The same host also serves other
  // internal static pages; this entry trusts that origin only. The retired `:8451` origin is
  // deliberately not listed.
  'https://lightning-node-1.gecko-snares.ts.net',
]);

/**
 * `<name>.pages.dev` subdomains of our own Cloudflare Pages projects. A preview deployment is
 * served at `<deployment or branch label>.<name>.pages.dev`, so for each name the bare host
 * and exactly one extra DNS label are first-party. No other `*.pages.dev` host is. Anyone who
 * can push a branch to one of these projects' repositories can publish on such a host.
 */
export const FIRST_PARTY_PAGES_SUBDOMAINS: readonly string[] = [
  // Pages project `tinychat`. tinychat: backend/src/cors-origins.ts:14.
  'tinychat-4jq',
  // Pages project `share`. share: README.md:45 (`--project-name share`). Previews cannot finish a
  // sign-in today (src/host/share-adapter.ts:823-825 is the origin predicate, :1201 the 403).
  'share-2fz',
  // Pages project `tinycloud-secrets`. secret-manager: .github/workflows/deploy.yml:31, wrangler.toml:1.
  'tinycloud-secrets',
  // Pages project `openkey-tinycloud-demo`: the OpenKey example app (js-sdk apps/openkey-example,
  // src/pages/Home.tsx:114-126, sign-in with no manifest) is served at its pages.dev host.
  'openkey-tinycloud-demo',
  // Not listed: Listen is retired (its host redirects to tinychat and no Pages project exists),
  // and `demo.tinycloud.xyz` only redirects.
];

const PAGES_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const PAGES_ORIGINS: readonly RegExp[] = FIRST_PARTY_PAGES_SUBDOMAINS.map(
  (name) => new RegExp(`^https://(?:${PAGES_LABEL}\\.)?${name}\\.pages\\.dev$`),
);

/** Is `origin`, the verified requesting origin, a first-party site for encryption outside `apps/`? */
export function isFirstPartyEncryptionOrigin(origin: unknown): boolean {
  if (typeof origin !== 'string') return false;
  return FIRST_PARTY_ENCRYPTION_ORIGINS.has(origin) || PAGES_ORIGINS.some((pattern) => pattern.test(origin));
}
