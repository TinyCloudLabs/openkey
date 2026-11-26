// Sign-in messages of two real apps, as the SDK builds them, for the tests of what a message lets a site do with
// spaces. The ReCap names no `tinycloud.space/host` ability: the account app asks to list spaces, TinyChat asks for
// one `info`.

import { prepareSession } from '@tinycloud/node-sdk-wasm';

const JWK = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const CHAT = 'xyz.tinycloud.tinychat';

function sdkMessage(owner: string, domain: string, space: string, abilities: Record<string, Record<string, string[]>>): string {
  const now = new Date();
  return prepareSession({
    address: owner, chainId: 1, domain, issuedAt: now.toISOString(), expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: `tinycloud:pkh:eip155:1:${owner}:${space}`, jwk: JWK, abilities,
  } as Parameters<typeof prepareSession>[0]).siwe;
}

/** https://account.tinycloud.xyz for an owner with spaces: reads and writes the account space, lists spaces, hosts none. */
export function accountAppMessage(owner: string): string {
  const account = `tinycloud:pkh:eip155:1:${owner}:account`;
  return sdkMessage(owner, 'account.tinycloud.xyz', 'account', {
    capabilities: { [account]: ['tinycloud.capabilities/read'] },
    delegation: { [account]: ['tinycloud.delegation/list', 'tinycloud.delegation/status'] },
    kv: {
      'applications/': ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/put'],
      'spaces/': ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/put'],
    },
    space: { [account]: ['tinycloud.space/list'] },
    sql: { '': ['tinycloud.sql/read'] },
  });
}

/** A TinyChat preview (a pages.dev origin) for an owner with spaces: one `tinycloud.space/info`, hosts none. */
export function tinyChatPreviewMessage(owner: string, domain: string): string {
  const apps = `tinycloud:pkh:eip155:1:${owner}:applications`;
  const kvAll = ['tinycloud.kv/del', 'tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata', 'tinycloud.kv/put'];
  return sdkMessage(owner, domain, 'applications', {
    space: { [apps]: ['tinycloud.space/info'] },
    capabilities: { [apps]: ['tinycloud.capabilities/read'] },
    hooks: { [`sql/${CHAT}/`]: ['tinycloud.hooks/subscribe'] },
    kv: {
      '': kvAll,
      [`${CHAT}/connectors/`]: kvAll,
      [`${CHAT}/threads/`]: kvAll,
      'exo/v1/jobs/': ['tinycloud.kv/del', 'tinycloud.kv/get', 'tinycloud.kv/put'],
      [`${CHAT}/connectors/transcripts/a`]: ['tinycloud.kv/get', 'tinycloud.kv/sync'],
      [`${CHAT}/connectors/transcripts/b`]: ['tinycloud.kv/get', 'tinycloud.kv/sync'],
    },
    sql: {
      [`${CHAT}/canvas`]: ['tinycloud.sql/read', 'tinycloud.sql/schema', 'tinycloud.sql/write'],
      [`${CHAT}/threads`]: ['tinycloud.sql/read', 'tinycloud.sql/schema', 'tinycloud.sql/write'],
    },
  });
}
