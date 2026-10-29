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
  // Listen. listen: packages/client/src/manifest.ts:53-59 (decrypt on the default network),
  // frontend/src/App.tsx:977-981 and :2001 (the grant in the sign-in request),
  // packages/client/src/openkey.ts:55-61 (personal_sign -> openkey.signMessage).
  'https://listen.tinycloud.xyz',
  // Secret Manager. secret-manager: src/lib/tinycloud-manifest.ts:38-42 (decrypt on the default
  // network), src/lib/vault-client.ts:64 and :76 (sign-in), :103-107 (network.create).
  'https://secrets.tinycloud.xyz',
  // TinyCloud OpenKey example app. js-sdk: apps/openkey-example/src/pages/Home.tsx:114-126
  // (sign-in with no manifest, so the SDK asks for decrypt on the default network). The mapping
  // of this host to that app is not confirmed in either repository.
  'https://demo.tinycloud.xyz',
]);

/**
 * `<name>.pages.dev` subdomains of our own Cloudflare Pages projects. A preview deployment is
 * served at `<deployment or branch label>.<name>.pages.dev`, so for each name the bare host
 * and exactly one extra DNS label are first-party. No other `*.pages.dev` host is.
 */
export const FIRST_PARTY_PAGES_SUBDOMAINS: readonly string[] = [
  // Pages project `tinychat`. tinychat: backend/src/cors-origins.ts:14.
  'tinychat-4jq',
  // Pages project `share`. share: README.md:45 (`--project-name share`). Previews cannot finish a
  // sign-in today (src/host/share-adapter.ts:823-826 and :1199-1201 answer 403 off the share origin).
  'share-2fz',
  // Pages project `tinycloud-secrets`. secret-manager: .github/workflows/deploy.yml:31, wrangler.toml:1.
  'tinycloud-secrets',
  // Pages project `openkey-tinycloud-demo`, served at demo.tinycloud.xyz (see the entry above).
  'openkey-tinycloud-demo',
  // Listen's Pages project is not in the Cloudflare account these subdomains were read from, so its
  // subdomain is unconfirmed (listen: wrangler.toml:1, .github/workflows/preview-phala-cloudflare.yml:45).
  // Add it here when it is known; until then Listen previews are not first-party.
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
