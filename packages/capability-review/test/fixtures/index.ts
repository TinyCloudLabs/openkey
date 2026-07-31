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

export const FIXTURE_META = {
  address: ADDR,
  chainId: CHAIN,
  ownSpace: SPACE,
  crossAppOwner: LISTEN_OWNER,
  crossAppSpace: LISTEN_SPACE,
  feedSpace: FEED_SPACE,
  issuedAt: ISSUED,
  expirationTime: EXPIRES,
};
