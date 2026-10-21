import { describe, expect, it } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverMessageAddress, type Hex } from 'viem';
import {
  adminAccountFor,
  classifyOrgSpaceMessage,
  isEd25519DidKey,
  isOrgSpaceSigningEnabled,
  kvCeiling,
  namesOrgSigningMessage,
  namesOrgSpaceMessage,
  ORG_SPACE_MAX_BYTES,
  ORG_SPACE_MAX_LIFETIME_MS,
  parseOrgSpaceMessage,
  renderOrgSpaceMessage,
  spaceIdFor,
  type OrgRole,
  type OrgSpaceAtt,
  type OrgSpaceParsed,
} from '../services/org-space-signing';

const ORIGIN = 'https://credentials.org';
const DOMAIN = 'credentials.org';
const NOW = new Date('2026-05-01T12:00:00.000Z');
const GRANT = 'grant_owner_1';
const DID_KEY = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';

// Anvil account 0. Public test key.
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as Hex;
const ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const OTHER_ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const SPACE = spaceIdFor(ADDRESS);
const CID = 'bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymzdp6v6b6rdgyz3m';

const ISO_NOW = NOW.toISOString();
const ISO_LATER = new Date(NOW.getTime() + 24 * 60 * 60 * 1000).toISOString();

type ClassifyCtx = Parameters<typeof classifyOrgSpaceMessage>[1];

function ctx(role: OrgRole = 'OWNER', overrides: Partial<ClassifyCtx> = {}): ClassifyCtx {
  return {
    allowedOrigins: [ORIGIN],
    requestingOrigin: ORIGIN,
    address: ADDRESS,
    grantId: GRANT,
    role,
    now: NOW,
    ...overrides,
  };
}

function hostParsed(overrides: Partial<OrgSpaceParsed> = {}): OrgSpaceParsed {
  return {
    domain: DOMAIN,
    address: ADDRESS,
    uri: SPACE,
    nonce: 'abcdefgh12',
    issuedAt: ISO_NOW,
    expirationTime: ISO_LATER,
    att: [
      { resource: `${SPACE}/space`, ability: 'tinycloud.space/host' },
      { resource: `${SPACE}/sql/shared-index`, ability: 'tinycloud.sql/admin' },
    ],
    fact: { adminAccount: adminAccountFor(ADDRESS), class: 'space-host', grantId: GRANT },
    ...overrides,
  };
}

function kvParsed(att: OrgSpaceAtt[], overrides: Partial<OrgSpaceParsed> = {}): OrgSpaceParsed {
  return hostParsed({
    uri: DID_KEY,
    att,
    fact: { adminAccount: adminAccountFor(ADDRESS), class: 'kv-delegation', grantId: GRANT },
    ...overrides,
  });
}

function revokeParsed(cid: string, overrides: Partial<OrgSpaceParsed> = {}): OrgSpaceParsed {
  return hostParsed({
    uri: SPACE,
    att: [{ resource: `urn:cid:${cid}`, ability: 'tinycloud.delegation/revoke' }],
    fact: { adminAccount: adminAccountFor(ADDRESS), class: 'delegation-revoke', grantId: GRANT },
    ...overrides,
  });
}

// A message the renderer will not produce. Used for classes that are not enabled, where
// the renderer refuses, and for shape tests. The statement line is a placeholder.
function rawMessage(att: OrgSpaceAtt[], fact: OrgSpaceParsed['fact'], overrides: Partial<OrgSpaceParsed> = {}): string {
  const resources: Record<string, Record<string, unknown[]>> = {};
  for (const { resource, ability } of att) (resources[resource] ??= {})[ability] = [{}];
  const payload = { att: resources, fct: [{ 'org-space': fact }] };
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const p = { ...hostParsed({ att, fact }), ...overrides };
  return [
    `${p.domain} wants you to sign in with your Ethereum account:`,
    p.address,
    '',
    'placeholder statement',
    '',
    `URI: ${p.uri}`,
    'Version: 1',
    'Chain ID: 1',
    `Nonce: ${p.nonce}`,
    `Issued At: ${p.issuedAt}`,
    `Expiration Time: ${p.expirationTime}`,
    'Resources:',
    `- urn:recap:${b64}`,
  ].join('\n');
}

function refusalOf(message: string, options: ClassifyCtx = ctx()) {
  const result = classifyOrgSpaceMessage(message, options);
  if (result.ok) throw new Error('expected refusal, got ok');
  return result.refusal;
}

describe('kind 2 feature flag and personal-route detection', () => {
  it('is on only for the literal string true', () => {
    expect(isOrgSpaceSigningEnabled({ ORG_SPACE_SIGNING_ENABLED: 'true' })).toBe(true);
    expect(isOrgSpaceSigningEnabled({ ORG_SPACE_SIGNING_ENABLED: 'false' })).toBe(false);
    expect(isOrgSpaceSigningEnabled({ ORG_SPACE_SIGNING_ENABLED: '1' })).toBe(false);
    expect(isOrgSpaceSigningEnabled({})).toBe(false);
  });

  it('names a rendered org-space message', () => {
    expect(namesOrgSpaceMessage(renderOrgSpaceMessage(hostParsed()))).toBe(true);
  });

  it('names an org-space message whose token will not decode (fails closed)', () => {
    expect(namesOrgSpaceMessage('site wants you\nurn:recap:!!!not-base64-json')).toBe(true);
  });

  it('does not name a plain SIWE message without a ReCap token', () => {
    expect(namesOrgSpaceMessage(`credentials.org wants you to sign in with your Ethereum account:\n${ADDRESS}`)).toBe(false);
  });

  it('names an org-space fact in a typed-data JSON carrying a single fct object', () => {
    const b64 = Buffer.from(JSON.stringify({ att: {}, fct: { 'org-space': {} } }), 'utf8').toString('base64url');
    expect(namesOrgSpaceMessage(`{"text":"urn:recap:${b64}"}`)).toBe(true);
  });

  it('names an att resource under an org space', () => {
    const b64 = Buffer.from(JSON.stringify({ att: { [`${SPACE}/kv/v1/shared/x`]: {} }, fct: [] }), 'utf8').toString('base64url');
    expect(namesOrgSpaceMessage(`urn:recap:${b64}`)).toBe(true);
  });

  it('namesOrgSigningMessage covers org-space messages', () => {
    expect(namesOrgSigningMessage(renderOrgSpaceMessage(hostParsed()))).toBe(true);
  });
});

describe('kind 2 enabled classes accept canonical messages', () => {
  it('space-host under OWNER returns the rendered text unchanged', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const result = classifyOrgSpaceMessage(message, ctx('OWNER'));
    expect(result).toEqual({ ok: true, kind: 'org-space/space-host', action: 'space-host', text: message, role: 'OWNER' });
  });

  it('kv-delegation under ADMIN is accepted across put, get, list, metadata and del ceiling paths', () => {
    const att: OrgSpaceAtt[] = [
      { resource: `${SPACE}/kv/v1/shared/${ADDRESS}/`, ability: 'tinycloud.kv/put' },
      { resource: `${SPACE}/kv/v1/config/`, ability: 'tinycloud.kv/put' },
      { resource: `${SPACE}/kv/v1/shared/`, ability: 'tinycloud.kv/get' },
      { resource: `${SPACE}/kv/v1/config/`, ability: 'tinycloud.kv/list' },
      { resource: `${SPACE}/kv/v1/shared/`, ability: 'tinycloud.kv/metadata' },
      { resource: `${SPACE}/kv/v1/shared/`, ability: 'tinycloud.kv/del' },
    ];
    const message = renderOrgSpaceMessage(kvParsed(att));
    const result = classifyOrgSpaceMessage(message, ctx('ADMIN'));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.role).toBe('ADMIN');
  });

  it('kv-delegation is also accepted under OWNER (OWNER satisfies ADMIN)', () => {
    const att = [{ resource: `${SPACE}/kv/v1/config/`, ability: 'tinycloud.kv/get' }];
    const message = renderOrgSpaceMessage(kvParsed(att));
    expect(classifyOrgSpaceMessage(message, ctx('OWNER')).ok).toBe(true);
  });

  it('delegation-revoke under OWNER is accepted', () => {
    const message = renderOrgSpaceMessage(revokeParsed(CID));
    const result = classifyOrgSpaceMessage(message, ctx('OWNER'));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.kind).toBe('org-space/delegation-revoke');
  });

  it('the signed text is recovered to the org key address (EIP-191)', async () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const account = privateKeyToAccount(ANVIL_KEY);
    expect(account.address).toBe(ADDRESS);
    const signature = await account.signMessage({ message });
    expect(await recoverMessageAddress({ message, signature })).toBe(ADDRESS);
  });
});

describe('kind 2 role gate (role is the locked grant role, not the caller claim)', () => {
  it('space-host requires OWNER: ADMIN is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_role_insufficient');
  });

  it('delegation-revoke requires OWNER: ADMIN is refused', () => {
    const message = renderOrgSpaceMessage(revokeParsed(CID));
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_role_insufficient');
  });

  it('kv-delegation accepts ADMIN', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/v1/config/`, ability: 'tinycloud.kv/get' }]));
    expect(classifyOrgSpaceMessage(message, ctx('ADMIN')).ok).toBe(true);
  });

  it('the result role is the rule role, so the caller cannot choose it', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const result = classifyOrgSpaceMessage(message, ctx('OWNER'));
    if (!result.ok) throw new Error('expected ok');
    expect(result.role).toBe('OWNER');
  });
});

describe('kind 2 placeholder classes are refused with class_not_enabled', () => {
  const placeholders: Array<{ cls: string; att: OrgSpaceAtt[] }> = [
    { cls: 'renewal-key', att: [{ resource: `${SPACE}/kv/v1/config/`, ability: 'tinycloud.kv/get' }] },
    { cls: 'sql-statement', att: [{ resource: `${SPACE}/sql/shared-index`, ability: 'tinycloud.sql/read' }] },
    { cls: 'writer-prefix', att: [{ resource: `${SPACE}/kv/v1/shared/${ADDRESS}/`, ability: 'tinycloud.kv/put' }] },
    { cls: 'hook', att: [{ resource: `${SPACE}/hooks/x`, ability: 'tinycloud.hooks/subscribe' }] },
    { cls: 'encryption', att: [{ resource: 'urn:tinycloud:encryption:x:mainnet', ability: 'tinycloud.encryption/decrypt' }] },
  ];
  for (const { cls, att } of placeholders) {
    it(`${cls} is refused even when the message is otherwise well formed`, () => {
      const message = rawMessage(att, { adminAccount: adminAccountFor(ADDRESS), class: cls, grantId: GRANT });
      expect(refusalOf(message)).toBe('org_space_class_not_enabled');
    });
  }
});

describe('kind 2 refusals in classifier order', () => {
  it('credentials capability is refused before anything else', () => {
    const message = rawMessage(
      [{ resource: `${SPACE}/kv/v1/config/`, ability: 'tinycloud.credentials/issue' }],
      { adminAccount: adminAccountFor(ADDRESS), class: 'kv-delegation', grantId: GRANT },
      { domain: 'attacker.example' },
    );
    expect(refusalOf(message)).toBe('credentials_capability_refused');
  });

  it('a disallowed requesting origin is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    expect(refusalOf(message, ctx('OWNER', { requestingOrigin: 'https://evil.example' }))).toBe('org_space_origin_mismatch');
  });

  it('an origin whose host matches the SIWE domain but is not allowed is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ domain: 'other.example' }));
    expect(refusalOf(message, ctx('OWNER', { requestingOrigin: 'https://other.example' }))).toBe('org_space_origin_mismatch');
  });

  it('a revoke whose uri is not the org space is refused', () => {
    const message = renderOrgSpaceMessage(revokeParsed(CID, { uri: spaceIdFor(OTHER_ADDRESS) }));
    expect(refusalOf(message)).toBe('org_space_resource_refused');
  });

  it('a SIWE domain that does not match the origin host is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ domain: 'other.example' }));
    expect(refusalOf(message)).toBe('org_space_origin_mismatch');
  });

  it('an address that is not the org key is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ address: OTHER_ADDRESS }));
    expect(refusalOf(message)).toBe('org_space_address_mismatch');
  });

  it('a grant that is not the active grant is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ fact: { adminAccount: adminAccountFor(ADDRESS), class: 'space-host', grantId: 'other' } }));
    expect(refusalOf(message)).toBe('org_space_grant_mismatch');
  });

  it('an adminAccount that is not the org key DID is refused', () => {
    const message = renderOrgSpaceMessage(
      hostParsed({ fact: { adminAccount: adminAccountFor(OTHER_ADDRESS), class: 'space-host', grantId: GRANT } }),
    );
    expect(refusalOf(message)).toBe('org_space_grant_mismatch');
  });

  it('a message that mixes classes is refused', () => {
    const message = rawMessage(
      [
        { resource: `${SPACE}/space`, ability: 'tinycloud.space/host' },
        { resource: `urn:cid:${CID}`, ability: 'tinycloud.delegation/revoke' },
      ],
      { adminAccount: adminAccountFor(ADDRESS), class: 'space-host', grantId: GRANT },
      { uri: SPACE },
    );
    expect(refusalOf(message)).toBe('org_space_mixed_classes');
  });

  it('a declared class that does not match the abilities is refused', () => {
    const message = rawMessage(
      [{ resource: `${SPACE}/space`, ability: 'tinycloud.space/host' }],
      { adminAccount: adminAccountFor(ADDRESS), class: 'kv-delegation', grantId: GRANT },
      { uri: SPACE },
    );
    expect(refusalOf(message)).toBe('org_space_class_mismatch');
  });

  it('an unrecognised ability is refused', () => {
    const message = rawMessage(
      [{ resource: `${SPACE}/kv/v1/config/`, ability: 'tinycloud.kv/unknown' }],
      { adminAccount: adminAccountFor(ADDRESS), class: 'kv-delegation', grantId: GRANT },
      { uri: DID_KEY },
    );
    expect(refusalOf(message)).toBe('org_space_ability_refused');
  });

  it('a non-empty caveat is refused as ability_refused', () => {
    const resources = { [`${SPACE}/kv/v1/config/`]: { 'tinycloud.kv/get': [{ path: 'x' }] } };
    const payload = { att: resources, fct: [{ 'org-space': { adminAccount: adminAccountFor(ADDRESS), class: 'kv-delegation', grantId: GRANT } }] };
    const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const message = rawMessage([], { adminAccount: '', class: '', grantId: '' }).replace(/- urn:recap:.*/, `- urn:recap:${b64}`);
    expect(refusalOf(message)).toBe('org_space_ability_refused');
  });

  it('a message over the byte cap is refused before parsing', () => {
    const message = renderOrgSpaceMessage(hostParsed()) + 'x'.repeat(ORG_SPACE_MAX_BYTES);
    expect(refusalOf(message)).toBe('org_space_too_large');
  });

  it('a non-SIWE text is refused as malformed', () => {
    expect(refusalOf('hello world')).toBe('org_space_malformed');
  });

  it('a chain other than 1 is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed()).replace('Chain ID: 1', 'Chain ID: 5');
    expect(refusalOf(message)).toBe('org_space_chain_refused');
  });
});

describe('kind 2 resource gates', () => {
  it('space-host outside the org space is refused', () => {
    const message = renderOrgSpaceMessage(
      hostParsed({ att: [{ resource: `tinycloud:pkh:eip155:1:${OTHER_ADDRESS}:org/space`, ability: 'tinycloud.space/host' }] }),
    );
    expect(refusalOf(message)).toBe('org_space_resource_refused');
  });

  it('space-host with an sql admin on another schema is refused as mixed classes', () => {
    const message = renderOrgSpaceMessage(
      hostParsed({ att: [{ resource: `${SPACE}/space`, ability: 'tinycloud.space/host' }, { resource: `${SPACE}/sql/other`, ability: 'tinycloud.sql/admin' }] }),
    );
    expect(refusalOf(message)).toBe('org_space_mixed_classes');
  });

  it('space-host URI that is not the space id is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ uri: DID_KEY }));
    expect(refusalOf(message)).toBe('org_space_resource_refused');
  });

  it('kv put to another writer segment is refused', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/v1/shared/${OTHER_ADDRESS}/`, ability: 'tinycloud.kv/put' }]));
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_resource_refused');
  });

  it('kv del outside shared/ is refused', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/v1/config/`, ability: 'tinycloud.kv/del' }]));
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_resource_refused');
  });

  it('kv resource outside the space prefix is refused', () => {
    const message = renderOrgSpaceMessage(
      kvParsed([{ resource: `tinycloud:pkh:eip155:1:${OTHER_ADDRESS}:org/kv/v1/config/`, ability: 'tinycloud.kv/get' }]),
    );
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_resource_refused');
  });

  it('kv recipient that is not an Ed25519 did:key is refused', () => {
    const message = renderOrgSpaceMessage(
      kvParsed([{ resource: `${SPACE}/kv/v1/config/`, ability: 'tinycloud.kv/get' }], { uri: 'did:pkh:eip155:1:0xabc' }),
    );
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_recipient_refused');
  });

  it('revoke of a non-CID resource is refused', () => {
    const message = renderOrgSpaceMessage(revokeParsed('notacid'));
    expect(refusalOf(message)).toBe('org_space_resource_refused');
  });

  it('revoke with two distinct resources is refused', () => {
    const OTHER_CID = 'bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yve5xp7r4k5q';
    const message = renderOrgSpaceMessage(
      revokeParsed(CID, {
        att: [
          { resource: `urn:cid:${CID}`, ability: 'tinycloud.delegation/revoke' },
          { resource: `urn:cid:${OTHER_CID}`, ability: 'tinycloud.delegation/revoke' },
        ],
      }),
    );
    expect(refusalOf(message)).toBe('org_space_resource_refused');
  });
});

describe('kind 2 time and lifetime gates', () => {
  it('issuedAt more than 5 minutes from now is refused', () => {
    const skewed = new Date(NOW.getTime() - 6 * 60 * 1000).toISOString();
    const message = renderOrgSpaceMessage(hostParsed({ issuedAt: skewed }));
    expect(refusalOf(message)).toBe('org_space_time_invalid');
  });

  it('issuedAt exactly 5 minutes from now is accepted', () => {
    const edge = new Date(NOW.getTime() - 5 * 60 * 1000).toISOString();
    const message = renderOrgSpaceMessage(hostParsed({ issuedAt: edge, expirationTime: ISO_LATER }));
    expect(classifyOrgSpaceMessage(message, ctx('OWNER')).ok).toBe(true);
  });

  it('an expiration at or before now is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ expirationTime: ISO_NOW }));
    expect(refusalOf(message)).toBe('org_space_time_invalid');
  });

  it('an expiration before issuedAt is refused', () => {
    const before = new Date(NOW.getTime() - 60 * 1000).toISOString();
    const message = renderOrgSpaceMessage(hostParsed({ expirationTime: before }));
    expect(refusalOf(message)).toBe('org_space_time_invalid');
  });

  it('an unparseable time is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ expirationTime: 'not a date' }));
    expect(refusalOf(message)).toBe('org_space_time_invalid');
  });

  it('a lifetime over 30 days is refused', () => {
    const over = new Date(NOW.getTime() + ORG_SPACE_MAX_LIFETIME_MS + 1000).toISOString();
    const message = renderOrgSpaceMessage(hostParsed({ expirationTime: over }));
    expect(refusalOf(message)).toBe('org_space_lifetime_exceeded');
  });

  it('a lifetime of exactly 30 days is accepted', () => {
    const exact = new Date(NOW.getTime() + ORG_SPACE_MAX_LIFETIME_MS).toISOString();
    const message = renderOrgSpaceMessage(hostParsed({ expirationTime: exact }));
    expect(classifyOrgSpaceMessage(message, ctx('OWNER')).ok).toBe(true);
  });

  it('the consent text shows the validity window', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const result = classifyOrgSpaceMessage(message, ctx('OWNER'));
    if (!result.ok) throw new Error('expected ok');
    expect(result.text).toContain(`Valid from ${ISO_NOW} until ${ISO_LATER}.`);
  });
});

describe('kind 2 canonical gate', () => {
  it('a statement line that does not match the rebuilt text is refused as not canonical', () => {
    const message = renderOrgSpaceMessage(hostParsed()).replace('Requires OWNER role.', 'requires OWNER role.');
    expect(refusalOf(message)).toBe('org_space_not_canonical');
  });

  it('a trailing newline is refused as malformed', () => {
    const message = `${renderOrgSpaceMessage(hostParsed())}\n`;
    expect(refusalOf(message)).toBe('org_space_malformed');
  });

  it('a payload with a non-canonical key order is refused as not canonical', () => {
    const resources = { [`${SPACE}/space`]: { 'tinycloud.space/host': [{}] } };
    const payload = {
      fct: [{ 'org-space': { grantId: GRANT, adminAccount: adminAccountFor(ADDRESS), class: 'space-host' } }],
      att: resources,
    };
    const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const message = renderOrgSpaceMessage(hostParsed({ att: [{ resource: `${SPACE}/space`, ability: 'tinycloud.space/host' }] })).replace(
      /- urn:recap:.*/,
      `- urn:recap:${b64}`,
    );
    expect(refusalOf(message)).toBe('org_space_not_canonical');
  });
});

describe('kind 2 kv ceiling and recipient helpers', () => {
  it('kvCeiling binds the put writer segment to the admin address', () => {
    const put = kvCeiling(ADDRESS)
      .filter((c) => c.ability === 'tinycloud.kv/put')
      .map((c) => c.path);
    expect(put).toEqual([`shared/${ADDRESS}/`, 'config/']);
  });

  it('isEd25519DidKey accepts a real Ed25519 did:key and rejects other methods', () => {
    expect(isEd25519DidKey(DID_KEY)).toBe(true);
    expect(isEd25519DidKey('did:pkh:eip155:1:0xabc')).toBe(false);
    expect(isEd25519DidKey('did:key:z')).toBe(false);
  });
});

describe('kind 2 parse exposes the fields the consent text is built from', () => {
  it('parses a rendered host message back to its fields', () => {
    const parsed = parseOrgSpaceMessage(renderOrgSpaceMessage(hostParsed()));
    expect(parsed.address).toBe(ADDRESS);
    expect(parsed.fact.class).toBe('space-host');
    expect(parsed.fact.grantId).toBe(GRANT);
    expect(parsed.att.map((a) => a.ability).sort()).toEqual(['tinycloud.space/host', 'tinycloud.sql/admin']);
  });
});
