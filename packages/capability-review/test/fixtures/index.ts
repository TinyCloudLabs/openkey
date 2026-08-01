// Test fixtures covering every classification branch. These are the exact
// samples the API and widget consume during regression tests.

const ADDR = "0x1111111111111111111111111111111111111111";
const CHAIN = 1;
const SPACE = `tinycloud:pkh:eip155:${CHAIN}:${ADDR}:default`;
const ISSUED = "2026-07-31T00:00:00.000Z";
const EXPIRES = "2026-08-07T00:00:00.000Z";

function siwe(resources: string[], overrides: Partial<{
  domain: string;
  address: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
  expirationTime: string;
  uri: string;
}> = {}): string {
  const d = overrides.domain ?? "cli.tinycloud.xyz";
  const a = overrides.address ?? ADDR;
  const c = overrides.chainId ?? CHAIN;
  const n = overrides.nonce ?? "abcdef123456";
  const i = overrides.issuedAt ?? ISSUED;
  const e = overrides.expirationTime ?? EXPIRES;
  const u = overrides.uri ?? `https://${d}`;
  return [
    `${d} wants you to sign in with your Ethereum account:`,
    a,
    "",
    "TinyCloud delegation",
    "",
    `URI: ${u}`,
    "Version: 1",
    `Chain ID: ${c}`,
    `Nonce: ${n}`,
    `Issued At: ${i}`,
    `Expiration Time: ${e}`,
    "Resources:",
    ...resources.map((r) => `- ${r}`),
  ].join("\n");
}

export const BOOTSTRAP_KV_SQL_CAPABILITIES = siwe([
  `tinycloud.kv/put:${SPACE}`,
  `tinycloud.kv/get:${SPACE}`,
  `tinycloud.kv/del:${SPACE}`,
  `tinycloud.sql/read:${SPACE}`,
  `tinycloud.sql/write:${SPACE}`,
  `tinycloud.capabilities/read:${SPACE}`,
]);

export const CHAT_APP_REQUEST = siwe([
  `tinycloud.kv/put:${SPACE}/chat/`,
  `tinycloud.kv/get:${SPACE}/chat/`,
  `tinycloud.capabilities/read:${SPACE}`,
]);

const FEED_SPACE = `tinycloud:pkh:eip155:${CHAIN}:${ADDR}:feed`;
export const FEED_APP_REQUEST = siwe([
  `tinycloud.kv/put:${FEED_SPACE}/inbox/`,
  `tinycloud.kv/get:${FEED_SPACE}/inbox/`,
  `tinycloud.capabilities/read:${FEED_SPACE}`,
]);

const LISTEN_OWNER = "0x2222222222222222222222222222222222222222";
const LISTEN_SPACE = `tinycloud:pkh:eip155:${CHAIN}:${LISTEN_OWNER}:listen`;
export const LISTEN_CROSS_APP_REQUEST = siwe([
  `tinycloud.kv/get:${LISTEN_SPACE}/transcripts/`,
  `tinycloud.capabilities/read:${LISTEN_SPACE}`,
]);

export const SECRETS_READ_REQUEST = siwe([
  `tinycloud.secrets/read:${SPACE}/mailchimp-api-key`,
  `tinycloud.capabilities/read:${SPACE}`,
]);

export const SECRETS_MUTATION_REQUEST = siwe([
  `tinycloud.secrets/write:${SPACE}/mailchimp-api-key`,
  `tinycloud.secrets/read:${SPACE}/mailchimp-api-key`,
  `tinycloud.capabilities/read:${SPACE}`,
]);

export const ENCRYPTION_DECRYPT_REQUEST = siwe([
  `tinycloud.encryption/decrypt:${SPACE}/health-data`,
  `tinycloud.capabilities/read:${SPACE}`,
]);

export const UNKNOWN_SERVICE_REQUEST = siwe([
  `some.experimental.service/frobnicate:${SPACE}/misc`,
  `tinycloud.capabilities/read:${SPACE}`,
]);

export const CYCLE_HEALTH_REQUEST = siwe([
  `tinycloud.kv/get:${SPACE}/cycle/`,
  `tinycloud.capabilities/read:${SPACE}`,
]);

export const ORDINARY_SIWE = [
  "example.com wants you to sign in with your Ethereum account:",
  ADDR,
  "",
  "Log in to Example",
  "",
  "URI: https://example.com/login",
  "Version: 1",
  `Chain ID: ${CHAIN}`,
  "Nonce: xyzxyzxyzxyz",
  `Issued At: ${ISSUED}`,
  `Expiration Time: ${EXPIRES}`,
].join("\n");

export const PLAIN_TEXT_MESSAGE =
  "Please sign this receipt: order #4472, amount 42 USD";

export const MALFORMED_SIWE = [
  "not-quite-siwe.example wants you to sign in with your Ethereum account:",
  // missing address line
  "URI: https://not-quite-siwe.example",
  "Chain ID: not-a-number",
].join("\n");

// ---------------------------------------------------------------------------
// Real ReCap fixtures (canonical urn:recap:<b64> wire form)
//
// TinyCloud SIWE messages carry capabilities as a base64url JSON payload keyed
// by resource URI, not as expanded `service/verb:space` resource lines. These
// fixtures mirror the real wire form so the parser is exercised end-to-end.
// ---------------------------------------------------------------------------

function base64UrlEncode(json: unknown): string {
  const s = JSON.stringify(json);
  // Node/Bun: Buffer is available and preserves UTF-8. Fall back to btoa when
  // Buffer is missing (browser test runners). btoa needs latin1 bytes.
  const bufferCtor = (globalThis as { Buffer?: { from(s: string, enc: string): { toString(enc: string): string } } })
    .Buffer;
  if (bufferCtor) {
    return bufferCtor.from(s, "utf8")
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Build a `urn:recap:<b64>` resource line from an att map. */
export function makeRecapResource(att: Record<string, Record<string, unknown[]>>): string {
  return `urn:recap:${base64UrlEncode({ att, prf: [] })}`;
}

// Canonical wire-form recap: bootstrap KV/SQL/capabilities in the default
// space. Matches what tinycloud-node emits for a bootstrap session.
export const REAL_RECAP_BOOTSTRAP = siwe([
  makeRecapResource({
    [SPACE]: {
      "tinycloud.kv/get": [{}],
      "tinycloud.kv/put": [{}],
      "tinycloud.kv/del": [{}],
      "tinycloud.sql/read": [{}],
      "tinycloud.sql/write": [{}],
      "tinycloud.capabilities/read": [{}],
    },
  }),
]);

// Real recap with a path inside the resource URI (matches accept.json vector
// pinned from tinycloud-node): `tinycloud:pkh:...:default/sql/xyz.tinycloud.listen/conversations`.
const RECAP_PATH = `${SPACE}/sql/xyz.tinycloud.listen/conversations`;
export const REAL_RECAP_WITH_PATH = siwe([
  makeRecapResource({
    [RECAP_PATH]: {
      "tinycloud.kv/get": [{}],
      "tinycloud.sql/read": [{}],
    },
  }),
]);

// Two recap resources given in one order for determinism testing.
export const REAL_RECAP_MIXED_A = siwe([
  makeRecapResource({
    [SPACE]: {
      "tinycloud.kv/put": [{}],
      "tinycloud.kv/get": [{}],
      "tinycloud.capabilities/read": [{}],
    },
    [FEED_SPACE]: {
      "tinycloud.sql/read": [{}],
    },
  }),
]);

// Same capabilities as A but the ability keys and att entries are in the
// reverse order. A deterministic parser must yield an identical model.
export const REAL_RECAP_MIXED_B = siwe([
  makeRecapResource({
    [FEED_SPACE]: {
      "tinycloud.sql/read": [{}],
    },
    [SPACE]: {
      "tinycloud.capabilities/read": [{}],
      "tinycloud.kv/get": [{}],
      "tinycloud.kv/put": [{}],
    },
  }),
]);

// Real-world tinycloud.kv path-based secrets (CLI uses tinycloud.kv with a
// vault/secrets/ path prefix rather than a separate tinycloud.secrets service).
// These must be classified as secret-read or secret-mutation, not bootstrap-kv.
const KV_SECRET_PATH = `${SPACE}/vault/secrets/DEPLOY_KEY`;
export const REAL_KV_SECRET_READ = siwe([
  makeRecapResource({
    [KV_SECRET_PATH]: {
      "tinycloud.kv/get": [{}],
    },
    [SPACE]: {
      "tinycloud.capabilities/read": [{}],
    },
  }),
]);

export const REAL_KV_SECRET_MUTATION = siwe([
  makeRecapResource({
    [KV_SECRET_PATH]: {
      "tinycloud.kv/put": [{}],
      "tinycloud.kv/get": [{}],
      "tinycloud.kv/del": [{}],
    },
    [SPACE]: {
      "tinycloud.capabilities/read": [{}],
    },
  }),
]);

export const FIXTURE_META = {
  address: ADDR,
  chainId: CHAIN,
  ownSpace: SPACE,
  crossAppOwner: LISTEN_OWNER,
  crossAppSpace: LISTEN_SPACE,
  feedSpace: FEED_SPACE,
  issuedAt: ISSUED,
  expirationTime: EXPIRES,
  recapPath: RECAP_PATH,
};

// Two SAME-service SAME-ability grants on different paths. This exists to
// exercise Sol MAJOR-6: a review-selection mapping must be able to pick one
// resource without collapsing the other. If the mapping keys by ability
// alone, both resources get selected/deselected together — a bug.
export const REAL_RECAP_SAME_ABILITY_TWO_PATHS = siwe([
  makeRecapResource({
    [`${SPACE}/chat`]: {
      "tinycloud.kv/get": [{}],
    },
    [`${SPACE}/feed`]: {
      "tinycloud.kv/get": [{}],
    },
    [SPACE]: {
      "tinycloud.capabilities/read": [{}],
    },
  }),
]);
