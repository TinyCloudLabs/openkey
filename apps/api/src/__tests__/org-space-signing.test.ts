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
  ORG_SPACE_CLOCK_SKEW_MS,
  ORG_SPACE_FACT,
  ORG_SPACE_MAX_BYTES,
  ORG_SPACE_MAX_LIFETIME_MS,
  parseOrgSpaceMessage,
  parseRfc3339Ms,
  renderOrgSpaceMessage,
  spaceIdFor,
  type OrgRole,
  type OrgSpaceAtt,
  type OrgSpaceParsed,
} from '../services/org-space-signing';

const ORIGIN = 'https://credentials.org';
const DOMAIN = 'credentials.org';
const NOW = new Date('2026-05-01T12:00:00.000Z');
const LATER = new Date(NOW.getTime() + 24 * 60 * 60 * 1000).toISOString();
const GRANT = 'grant_owner_1';
const DID_KEY = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const CID = 'bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymzdp6v6b6rdgyz3m';
const OTHER_CID = 'bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yve5xp7r4k5q';

// Anvil account 0: the org key. Public test key.
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as Hex;
const ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
// Anvil account 1: the grantee's canonical TinyCloud key. This is the admin.
const ADMIN_ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
// Anvil account 2: an unrelated key.
const OTHER_ADDRESS = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const SPACE = spaceIdFor(ADDRESS);

type ClassifyCtx = Parameters<typeof classifyOrgSpaceMessage>[1];

type RecapPayload = {
  att: Record<string, Record<string, unknown[]>>;
  fct: Array<Record<string, Record<string, unknown>>>;
  prf: unknown[];
};

function ctx(role: OrgRole = 'OWNER', overrides: Partial<ClassifyCtx> = {}): ClassifyCtx {
  return {
    allowedOrigins: [ORIGIN],
    requestingOrigin: ORIGIN,
    address: ADDRESS,
    adminAddress: ADMIN_ADDRESS,
    grantId: GRANT,
    role,
    now: NOW,
    ...overrides,
  };
}

function hostAtt(): OrgSpaceAtt[] {
  return [
    { resource: `${SPACE}/space`, ability: 'tinycloud.space/host' },
    { resource: `${SPACE}/sql/shared-index`, ability: 'tinycloud.sql/admin' },
  ];
}

function hostParsed(overrides: Partial<OrgSpaceParsed> = {}): OrgSpaceParsed {
  return {
    domain: DOMAIN,
    address: ADDRESS,
    uri: DID_KEY,
    nonce: 'abcdefgh12',
    issuedAt: NOW.toISOString(),
    expirationTime: LATER,
    att: hostAtt(),
    fact: { adminAccount: adminAccountFor(ADMIN_ADDRESS), class: 'space-host', grantId: GRANT },
    ...overrides,
  };
}

function kvParsed(att: OrgSpaceAtt[], overrides: Partial<OrgSpaceParsed> = {}): OrgSpaceParsed {
  return hostParsed({
    att,
    fact: { adminAccount: adminAccountFor(ADMIN_ADDRESS), class: 'kv-delegation', grantId: GRANT },
    ...overrides,
  });
}

function revokeParsed(cid: string, overrides: Partial<OrgSpaceParsed> = {}): OrgSpaceParsed {
  return hostParsed({
    uri: SPACE,
    att: [{ resource: `urn:cid:${cid}`, ability: 'tinycloud.delegation/revoke' }],
    fact: { adminAccount: adminAccountFor(ADMIN_ADDRESS), class: 'delegation-revoke', grantId: GRANT },
    ...overrides,
  });
}

const KV_ADMIN_ATT: OrgSpaceAtt[] = [
  { resource: `${SPACE}/kv/shared/${ADMIN_ADDRESS}/`, ability: 'tinycloud.kv/put' },
  { resource: `${SPACE}/kv/config/`, ability: 'tinycloud.kv/put' },
  { resource: `${SPACE}/kv/shared/`, ability: 'tinycloud.kv/get' },
  { resource: `${SPACE}/kv/config/`, ability: 'tinycloud.kv/list' },
  { resource: `${SPACE}/kv/shared/`, ability: 'tinycloud.kv/metadata' },
  { resource: `${SPACE}/kv/shared/`, ability: 'tinycloud.kv/del' },
];

// The token is base64url over the JSON payload. These helpers read and rewrite it so
// tests can break one field of an otherwise rendered message.
function recapToken(message: string): string {
  const token = /urn:recap:([A-Za-z0-9_=-]+)/.exec(message)?.[1];
  if (!token) throw new Error('no recap token in fixture');
  return token;
}

function readPayload(message: string): RecapPayload {
  return JSON.parse(Buffer.from(recapToken(message), 'base64url').toString('utf8')) as RecapPayload;
}

function withPayload(message: string, payload: unknown): string {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return message.replace(recapToken(message), encoded);
}

function withFactClass(message: string, cls: string): string {
  const payload = readPayload(message);
  const value = payload.fct[0]?.[ORG_SPACE_FACT];
  if (!value) throw new Error('no fact in fixture');
  value.class = cls;
  return withPayload(message, payload);
}

function refusalOf(message: string, options: ClassifyCtx = ctx()): string {
  const result = classifyOrgSpaceMessage(message, options);
  if (result.ok) throw new Error(`expected refusal, got ok ${result.kind}`);
  return result.refusal;
}

function acceptOf(message: string, options: ClassifyCtx = ctx()) {
  const result = classifyOrgSpaceMessage(message, options);
  if (!result.ok) throw new Error(`expected ok, got refusal ${result.refusal}`);
  return result;
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
    const b64 = Buffer.from(JSON.stringify({ att: { [`${SPACE}/kv/shared/x`]: {} }, fct: [] }), 'utf8').toString('base64url');
    expect(namesOrgSpaceMessage(`urn:recap:${b64}`)).toBe(true);
  });

  it('namesOrgSigningMessage covers org-space messages', () => {
    expect(namesOrgSigningMessage(renderOrgSpaceMessage(hostParsed()))).toBe(true);
  });
});

describe('kind 2 accepts canonical node-format messages', () => {
  it('space-host under OWNER returns the rendered text unchanged', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    expect(acceptOf(message)).toEqual({
      ok: true,
      kind: 'org-space/space-host',
      action: 'space-host',
      text: message,
      role: 'OWNER',
    });
  });

  it('kv-delegation under ADMIN is accepted across put, get, list, metadata and del ceiling paths', () => {
    const message = renderOrgSpaceMessage(kvParsed(KV_ADMIN_ATT));
    const result = acceptOf(message, ctx('ADMIN'));
    expect(result.kind).toBe('org-space/kv-delegation');
    expect(result.role).toBe('ADMIN');
  });

  it('kv-delegation is also accepted under OWNER', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/config/`, ability: 'tinycloud.kv/get' }]));
    expect(acceptOf(message, ctx('OWNER')).ok).toBe(true);
  });

  it('delegation-revoke under OWNER is accepted', () => {
    const message = renderOrgSpaceMessage(revokeParsed(CID));
    expect(acceptOf(message, ctx('OWNER')).kind).toBe('org-space/delegation-revoke');
  });

  it('the signed text is recovered to the org key address (EIP-191) and is accepted', async () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const account = privateKeyToAccount(ANVIL_KEY);
    expect(account.address).toBe(ADDRESS);
    const signature = await account.signMessage({ message });
    expect(await recoverMessageAddress({ message, signature })).toBe(ADDRESS);
    expect(acceptOf(message).ok).toBe(true);
  });
});

describe('kind 2 role gate (role is the locked grant role, not the caller claim)', () => {
  it('space-host requires OWNER: ADMIN is refused', () => {
    expect(refusalOf(renderOrgSpaceMessage(hostParsed()), ctx('ADMIN'))).toBe('org_space_role_insufficient');
  });

  it('delegation-revoke requires OWNER: ADMIN is refused', () => {
    expect(refusalOf(renderOrgSpaceMessage(revokeParsed(CID)), ctx('ADMIN'))).toBe('org_space_role_insufficient');
  });

  it('the result role is the rule role, not the caller role', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/config/`, ability: 'tinycloud.kv/get' }]));
    expect(acceptOf(message, ctx('OWNER')).role).toBe('ADMIN');
  });
});

describe('kind 2 class gates', () => {
  const base = () => renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/config/`, ability: 'tinycloud.kv/get' }]));
  for (const cls of ['renewal-key', 'sql-statement', 'writer-prefix', 'hook', 'encryption']) {
    it(`${cls} is refused as class_not_enabled`, () => {
      expect(refusalOf(withFactClass(base(), cls))).toBe('org_space_class_not_enabled');
    });
  }

  it('an unknown class name is refused as malformed', () => {
    expect(refusalOf(withFactClass(base(), 'bogus'))).toBe('org_space_malformed');
  });

  it('a message that mixes host and revoke abilities is refused as mixed classes', () => {
    const message = renderOrgSpaceMessage(
      hostParsed({
        att: [...hostAtt(), { resource: `urn:cid:${CID}`, ability: 'tinycloud.delegation/revoke' }],
      }),
    );
    expect(refusalOf(message)).toBe('org_space_mixed_classes');
  });

  it('a non-shared-index sql admin mixed with host is refused as mixed classes', () => {
    const message = renderOrgSpaceMessage(
      hostParsed({ att: [{ resource: `${SPACE}/space`, ability: 'tinycloud.space/host' }, { resource: `${SPACE}/sql/other`, ability: 'tinycloud.sql/admin' }] }),
    );
    expect(refusalOf(message)).toBe('org_space_mixed_classes');
  });

  it('a declared class that does not match the derived class is refused as class_mismatch', () => {
    const message = renderOrgSpaceMessage(kvParsed(hostAtt()));
    expect(refusalOf(message, ctx('OWNER'))).toBe('org_space_class_mismatch');
  });

  it('an unrecognised ability is refused as ability_refused', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/config/`, ability: 'tinycloud.kv/unknown' }]));
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_ability_refused');
  });

  it('a non-empty caveat is refused as ability_refused', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/config/`, ability: 'tinycloud.kv/get' }]));
    const payload = readPayload(message);
    const ability = payload.att[`${SPACE}/kv/config/`];
    if (!ability) throw new Error('fixture resource missing');
    ability['tinycloud.kv/get'] = [{ path: 'x' }];
    expect(refusalOf(withPayload(message, payload), ctx('ADMIN'))).toBe('org_space_ability_refused');
  });

  it('a credentials ability is refused before origin and address checks', () => {
    const message = renderOrgSpaceMessage(
      kvParsed([{ resource: `${SPACE}/kv/config/`, ability: 'tinycloud.credentials/issue' }], { domain: 'attacker.example' }),
    );
    expect(refusalOf(message)).toBe('credentials_capability_refused');
  });
});

describe('kind 2 origin, identity and grant gates', () => {
  it('a requesting origin outside the allow list is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    expect(refusalOf(message, ctx('OWNER', { requestingOrigin: 'https://evil.example' }))).toBe('org_space_origin_mismatch');
  });

  it('the SIWE domain must match the requesting origin host, even when the origin is allowed', () => {
    const message = renderOrgSpaceMessage(hostParsed({ domain: DOMAIN }));
    const options = ctx('OWNER', {
      allowedOrigins: [ORIGIN, 'https://other.example'],
      requestingOrigin: 'https://other.example',
    });
    expect(refusalOf(message, options)).toBe('org_space_origin_mismatch');
  });

  it('an address that is not the org key is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ address: ADMIN_ADDRESS }));
    expect(refusalOf(message)).toBe('org_space_address_mismatch');
  });

  it('a grant id that is not the active grant is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ fact: { adminAccount: adminAccountFor(ADMIN_ADDRESS), class: 'space-host', grantId: 'other' } }));
    expect(refusalOf(message)).toBe('org_space_grant_mismatch');
  });

  it('an adminAccount that is the org key rather than the grantee admin is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ fact: { adminAccount: adminAccountFor(ADDRESS), class: 'space-host', grantId: GRANT } }));
    expect(refusalOf(message)).toBe('org_space_grant_mismatch');
  });
});

describe('kind 2 resource and recipient gates', () => {
  it('space-host outside the org space is refused', () => {
    const message = renderOrgSpaceMessage(
      hostParsed({ att: [{ resource: `tinycloud:pkh:eip155:1:${ADMIN_ADDRESS}:org/space`, ability: 'tinycloud.space/host' }, ...hostAtt().slice(1)] }),
    );
    expect(refusalOf(message)).toBe('org_space_resource_refused');
  });

  it('space-host without the shared-index schema grant is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ att: hostAtt().slice(0, 1) }));
    expect(refusalOf(message)).toBe('org_space_resource_refused');
  });

  it('space-host schema grant without the host grant is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ att: hostAtt().slice(1) }));
    expect(refusalOf(message)).toBe('org_space_resource_refused');
  });

  it('space-host whose URI is the space id rather than a staged did:key is refused as recipient', () => {
    const message = renderOrgSpaceMessage(hostParsed({ uri: SPACE }));
    expect(refusalOf(message)).toBe('org_space_recipient_refused');
  });

  it('space-host whose URI is a did:pkh is refused as recipient', () => {
    const message = renderOrgSpaceMessage(hostParsed({ uri: 'did:pkh:eip155:1:0xabc' }));
    expect(refusalOf(message)).toBe('org_space_recipient_refused');
  });

  it('kv put to the org key writer segment is refused (writer is the admin)', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/shared/${ADDRESS}/`, ability: 'tinycloud.kv/put' }]));
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_resource_refused');
  });

  it('kv put without a writer segment is refused', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/shared/`, ability: 'tinycloud.kv/put' }]));
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_resource_refused');
  });

  it('kv del outside shared/ is refused', () => {
    const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/config/`, ability: 'tinycloud.kv/del' }]));
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_resource_refused');
  });

  it('kv resource outside the space prefix is refused', () => {
    const message = renderOrgSpaceMessage(
      kvParsed([{ resource: `tinycloud:pkh:eip155:1:${ADMIN_ADDRESS}:org/kv/config/`, ability: 'tinycloud.kv/get' }]),
    );
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_resource_refused');
  });

  it('kv dot segments cannot escape the ceiling prefix', () => {
    for (const path of ['shared/../secret/', 'config/../secret/', 'shared/%2e%2e/secret/', 'shared/./x/']) {
      const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/${path}`, ability: 'tinycloud.kv/get' }]));
      expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_resource_refused');
    }
  });

  it('kv paths outside the segment grammar are refused', () => {
    for (const path of ['shared/a*b/', 'shared/a%20b/', 'shared//x/', 'shared/a b/']) {
      const message = renderOrgSpaceMessage(kvParsed([{ resource: `${SPACE}/kv/${path}`, ability: 'tinycloud.kv/get' }]));
      expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_resource_refused');
    }
  });

  it('kv recipient that is not an Ed25519 did:key is refused', () => {
    const message = renderOrgSpaceMessage(
      kvParsed([{ resource: `${SPACE}/kv/config/`, ability: 'tinycloud.kv/get' }], { uri: 'did:pkh:eip155:1:0xabc' }),
    );
    expect(refusalOf(message, ctx('ADMIN'))).toBe('org_space_recipient_refused');
  });

  it('revoke of a non-CID resource is refused', () => {
    expect(refusalOf(renderOrgSpaceMessage(revokeParsed('notacid')))).toBe('org_space_resource_refused');
  });

  it('revoke with two resources is refused', () => {
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

  it('revoke whose URI is not the org space is refused', () => {
    const message = renderOrgSpaceMessage(revokeParsed(CID, { uri: spaceIdFor(ADMIN_ADDRESS) }));
    expect(refusalOf(message)).toBe('org_space_resource_refused');
  });
});

describe('kind 2 time and lifetime gates', () => {
  const at = (ms: number) => new Date(NOW.getTime() + ms).toISOString();
  const SKEW = ORG_SPACE_CLOCK_SKEW_MS;

  it('issuedAt beyond the clock skew in the past is refused', () => {
    expect(refusalOf(renderOrgSpaceMessage(hostParsed({ issuedAt: at(-SKEW - 1) })))).toBe('org_space_time_invalid');
  });

  it('issuedAt beyond the clock skew in the future is refused', () => {
    expect(refusalOf(renderOrgSpaceMessage(hostParsed({ issuedAt: at(SKEW + 1), expirationTime: at(SKEW + 60_000) })))).toBe(
      'org_space_time_invalid',
    );
  });

  it('issuedAt exactly at the clock skew is accepted', () => {
    expect(acceptOf(renderOrgSpaceMessage(hostParsed({ issuedAt: at(-SKEW) }))).ok).toBe(true);
  });

  it('an expiration at or before now is refused, even when after issuedAt', () => {
    const message = renderOrgSpaceMessage(hostParsed({ issuedAt: at(-4 * 60_000), expirationTime: at(-60_000) }));
    expect(refusalOf(message)).toBe('org_space_time_invalid');
  });

  it('an expiration at or before issuedAt is refused, even when after now', () => {
    const message = renderOrgSpaceMessage(hostParsed({ issuedAt: at(3 * 60_000), expirationTime: at(2 * 60_000) }));
    expect(refusalOf(message)).toBe('org_space_time_invalid');
  });

  it('an unparseable time is refused', () => {
    expect(refusalOf(renderOrgSpaceMessage(hostParsed({ expirationTime: 'not a date' })))).toBe('org_space_time_invalid');
  });

  it('a lifetime over 30 days is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed({ expirationTime: at(ORG_SPACE_MAX_LIFETIME_MS + 1000) }));
    expect(refusalOf(message)).toBe('org_space_lifetime_exceeded');
  });

  it('a lifetime of exactly 30 days is accepted', () => {
    const message = renderOrgSpaceMessage(hostParsed({ expirationTime: at(ORG_SPACE_MAX_LIFETIME_MS) }));
    expect(acceptOf(message).ok).toBe(true);
  });

  it('the lifetime is measured from issuedAt, not from now', () => {
    const message = renderOrgSpaceMessage(hostParsed({ issuedAt: at(-SKEW), expirationTime: at(ORG_SPACE_MAX_LIFETIME_MS - 60_000) }));
    expect(refusalOf(message)).toBe('org_space_lifetime_exceeded');
  });
});

describe('kind 2 RFC 3339 parser', () => {
  it('accepts Z and numeric offsets and returns the same instant', () => {
    const utc = Date.UTC(2026, 4, 1, 12, 0, 0);
    expect(parseRfc3339Ms('2026-05-01T12:00:00Z')).toBe(utc);
    expect(parseRfc3339Ms('2026-05-01T17:30:00+05:30')).toBe(utc);
    expect(parseRfc3339Ms('2026-05-01T12:00:00.000Z')).toBe(utc);
  });

  it('rejects forms Date.parse would accept', () => {
    expect(parseRfc3339Ms('May 1, 2026')).toBeNull();
    expect(parseRfc3339Ms('2026-05-01 12:00:00Z')).toBeNull();
    expect(parseRfc3339Ms('2026-05-01T12:00:00')).toBeNull();
  });

  it('rejects impossible calendar dates', () => {
    expect(parseRfc3339Ms('2026-02-30T00:00:00Z')).toBeNull();
  });
});

describe('kind 2 payload shape', () => {
  it('a non-empty prf is refused as malformed', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const payload = readPayload(message);
    payload.prf = [{}];
    expect(refusalOf(withPayload(message, payload))).toBe('org_space_malformed');
  });

  it('a payload without prf is refused as malformed', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const payload = readPayload(message);
    expect(refusalOf(withPayload(message, { att: payload.att, fct: payload.fct }))).toBe('org_space_malformed');
  });

  it('an extra top-level payload key is refused as malformed', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const payload = readPayload(message);
    expect(refusalOf(withPayload(message, { ...payload, extra: 1 }))).toBe('org_space_malformed');
  });

  it('an extra fact key is refused as malformed', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const payload = readPayload(message);
    const value = payload.fct[0]?.[ORG_SPACE_FACT];
    if (!value) throw new Error('no fact in fixture');
    value.extra = 'x';
    expect(refusalOf(withPayload(message, payload))).toBe('org_space_malformed');
  });

  it('a message over the byte cap is refused before parsing', () => {
    const message = renderOrgSpaceMessage(hostParsed()) + 'x'.repeat(ORG_SPACE_MAX_BYTES);
    expect(refusalOf(message)).toBe('org_space_too_large');
  });

  it('non-SIWE text is refused as malformed', () => {
    expect(refusalOf('hello world')).toBe('org_space_malformed');
  });

  it('a chain other than 1 is refused', () => {
    const message = renderOrgSpaceMessage(hostParsed()).replace('Chain ID: 1', 'Chain ID: 5');
    expect(refusalOf(message)).toBe('org_space_chain_refused');
  });
});

describe('kind 2 canonical gate (the signed text is rebuilt from the fields)', () => {
  it('a statement line that does not match the fields is refused as not canonical', () => {
    const lines = renderOrgSpaceMessage(hostParsed()).split('\n');
    lines[3] = 'Grant everything.';
    expect(refusalOf(lines.join('\n'))).toBe('org_space_not_canonical');
  });

  it('a trailing newline is refused as malformed', () => {
    expect(refusalOf(`${renderOrgSpaceMessage(hostParsed())}\n`)).toBe('org_space_malformed');
  });

  it('a payload with reordered top-level keys is refused as not canonical', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const payload = readPayload(message);
    expect(refusalOf(withPayload(message, { prf: payload.prf, fct: payload.fct, att: payload.att }))).toBe('org_space_not_canonical');
  });

  it('a payload with reordered att resources is refused as not canonical', () => {
    const message = renderOrgSpaceMessage(hostParsed());
    const payload = readPayload(message);
    const reversed = Object.fromEntries(Object.entries(payload.att).reverse());
    expect(refusalOf(withPayload(message, { att: reversed, fct: payload.fct, prf: payload.prf }))).toBe('org_space_not_canonical');
  });
});

describe('kind 2 kv ceiling and recipient helpers', () => {
  it('kvCeiling binds the put writer segment to the admin address', () => {
    const put = kvCeiling(ADMIN_ADDRESS)
      .filter((c) => c.ability === 'tinycloud.kv/put')
      .map((c) => c.path);
    expect(put).toEqual([`shared/${ADMIN_ADDRESS}/`, 'config/']);
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
    expect(parsed).toMatchObject({
      address: ADDRESS,
      uri: DID_KEY,
      fact: { adminAccount: adminAccountFor(ADMIN_ADDRESS), class: 'space-host', grantId: GRANT },
    });
    expect(parsed.att.map((a) => a.ability).sort()).toEqual(['tinycloud.space/host', 'tinycloud.sql/admin']);
  });
});
