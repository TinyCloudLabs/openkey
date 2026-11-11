import { afterAll, beforeAll, expect, test } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { acceptAdmin, inviteAdmin } from '../services/org-key-admins';
import { addPasskey, assertionFor } from './org-keys-fixtures';

const postgresUrl = process.env.OPENKEY_ADMIN_TEST_POSTGRES_URL;
if (postgresUrl && !['127.0.0.1', 'localhost'].includes(new URL(postgresUrl).hostname)) throw new Error('This test requires a disposable loopback database');
const pool = postgresUrl ? new Pool({ connectionString: postgresUrl }) : null;
const embedded = pool ? null : new PGlite();
const db = embedded ?? { exec: async (sql: string) => pool!.query(sql), close: async () => pool!.end() };
const prisma = new PrismaClient({ adapter: pool ? new PrismaPg({ connectionString: postgresUrl! }) : new PrismaPGlite(embedded!) });
const origin = 'https://openkey.test';
const owner = { userId: 'owner', sessionId: 'owner-session', origin, rpId: 'openkey.test' };
const invitee = { ...owner, userId: 'invitee', sessionId: 'invitee-session' };
const state = { passkeys: [] as Record<string, unknown>[] };
const ownerPasskey = addPasskey(state, 'owner');
const inviteePasskey = addPasskey(state, 'invitee');

beforeAll(async () => {
  const root = new URL('../../../../packages/db/prisma/migrations/', import.meta.url);
  for (const name of (await readdir(root)).sort()) {
    if (name === 'migration_lock.toml') continue;
    await db.exec(await readFile(new URL(`${name}/migration.sql`, root), 'utf8'));
  }
  for (const id of ['owner', 'invitee']) {
    await prisma.user.create({ data: { id, email: `${id}@example.test`, emailVerified: true } });
    await prisma.session.create({ data: { id: `${id}-session`, token: `${id}-token`, userId: id, expiresAt: new Date(Date.now() + 3600000) } });
  }
  for (const passkey of state.passkeys) await prisma.passkey.create({ data: { ...passkey, deviceType: 'singleDevice', backedUp: false } as never });
  await prisma.ethereumKey.create({ data: { id: 'org-key', userId: null, address: '0x0000000000000000000000000000000000000001', publicKey: 'public', custody: 'ORG', keyType: 'MANAGED', sealingContext: 'A'.repeat(43), isCanonicalTinyCloud: false } });
  await prisma.orgKey.create({ data: { keyId: 'org-key', orgId: 'org', orgName: 'Example', controllerDid: 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001' } });
  await prisma.keyGrant.create({ data: { id: 'owner-grant', keyId: 'org-key', role: 'OWNER', granteeUserId: 'owner', acceptedAt: new Date() } });
  await prisma.ethereumKey.create({ data: { id: 'personal-key', userId: 'invitee', address: '0x52908400098527886E0F7030069857D2E4169EE7', publicKey: 'personal', custody: 'PERSONAL', keyType: 'MANAGED', isCanonicalTinyCloud: true } });
}, 60_000);
afterAll(async () => { await prisma.$disconnect(); await db.close(); });

test('owner invites an account and its verified personal identity explicitly accepts once', async () => {
  const issued = await inviteAdmin(prisma, owner, 'org-key', { accountId: 'invitee' });
  const inviteChallenge = challengeOf(issued);
  const invitation = await inviteAdmin(prisma, owner, 'org-key', { accountId: 'invitee' }, {
    nonce: inviteChallenge.nonce, assertion: assertionFor(ownerPasskey, inviteChallenge.challenge, { origin, rpID: owner.rpId }),
  });
  if (!invitation || typeof invitation !== 'object' || !('invitationId' in invitation)) throw new Error('No invitation');
  const id = String(invitation.invitationId);
  const pending = await prisma.keyGrant.findUniqueOrThrow({ where: { id } });
  expect(pending.acceptedAt).toBeNull();
  expect(pending.granteeUserId).toBeNull();
  const acceptance = await acceptAdmin(prisma, invitee, id);
  const acceptChallenge = challengeOf(acceptance);
  const proof = { nonce: acceptChallenge.nonce, assertion: assertionFor(inviteePasskey, acceptChallenge.challenge, { origin, rpID: invitee.rpId }) };
  expect(await acceptAdmin(prisma, invitee, id, proof)).toEqual({ keyId: 'org-key' });
  expect(await acceptAdmin(prisma, invitee, id, proof)).toEqual({ keyId: 'org-key' });
  const accepted = await prisma.keyGrant.findUniqueOrThrow({ where: { id } });
  expect(accepted.granteeUserId).toBe('invitee');
  expect(accepted.granteeDid).toBe('did:pkh:eip155:1:0x52908400098527886E0F7030069857D2E4169EE7');
  expect(await prisma.keyGrantEvent.count({ where: { grantId: id, kind: 'accepted' } })).toBe(1);
});

function challengeOf(value: unknown): { nonce: string; challenge: string } {
  if (!value || typeof value !== 'object' || !('challenge' in value)) throw new Error('No challenge');
  const result = value.challenge;
  if (!result || typeof result !== 'object' || !('nonce' in result) || !('challenge' in result)
    || typeof result.nonce !== 'string' || typeof result.challenge !== 'string') throw new Error('Invalid challenge');
  return { nonce: result.nonce, challenge: result.challenge };
}

test('acceptance refuses wrong account, expiry, cancellation and changed personal identity', async () => {
  for (const [id, data] of [
    ['wrong-account', { invitedUserId: 'owner' }],
    ['expired', { invitationExpiresAt: new Date(0) }],
    ['cancelled', { revokedAt: new Date() }],
  ] as const) {
    await prisma.keyGrant.create({ data: { id, keyId: 'org-key', role: 'ADMIN', invitedUserId: 'invitee', invitationExpiresAt: new Date(Date.now() + 60000), ...data } });
    await expect(acceptAdmin(prisma, invitee, id)).rejects.toThrow('Forbidden');
  }
  await prisma.keyGrant.create({ data: { id: 'identity-change', keyId: 'org-key', role: 'ADMIN', invitedUserId: 'invitee', invitationExpiresAt: new Date(Date.now() + 60000) } });
  const challenge = challengeOf(await acceptAdmin(prisma, invitee, 'identity-change'));
  await prisma.ethereumKey.update({ where: { id: 'personal-key' }, data: { address: '0x0000000000000000000000000000000000000002' } });
  await expect(acceptAdmin(prisma, invitee, 'identity-change', { nonce: challenge.nonce, assertion: assertionFor(inviteePasskey, challenge.challenge, { counter: 2, origin, rpID: invitee.rpId }) })).rejects.toThrow('Forbidden');
  expect((await prisma.keyGrant.findUniqueOrThrow({ where: { id: 'identity-change' } })).acceptedAt).toBeNull();
  await prisma.ethereumKey.update({ where: { id: 'personal-key' }, data: { address: '0x52908400098527886E0F7030069857D2E4169EE7' } });
});

test('only a live secret email link discloses a masked target; no ID or org data', async () => {
  const { createHash } = await import('node:crypto');
  const { maskedInvitation } = await import('../services/org-key-admins');
  const token = 'a'.repeat(43);
  await prisma.keyGrant.create({ data: { id: 'masked', keyId: 'org-key', role: 'ADMIN', invitedEmail: 'jules@example.test', invitationTokenDigest: createHash('sha256').update(token).digest('hex'), invitationExpiresAt: new Date(Date.now() + 60000) } });
  expect(await maskedInvitation(prisma, 'no-such', token)).toEqual({ maskedEmail: null });
  expect(await maskedInvitation(prisma, 'masked', undefined)).toEqual({ maskedEmail: null });
  expect(await maskedInvitation(prisma, 'masked', 'wrong')).toEqual({ maskedEmail: null });
  expect(await maskedInvitation(prisma, 'masked', token)).toEqual({ maskedEmail: 'j•••@example.test' });
  await prisma.keyGrant.update({ where: { id: 'masked' }, data: { invitationExpiresAt: new Date(0) } });
  expect(await maskedInvitation(prisma, 'masked', token)).toEqual({ maskedEmail: null });
});

test('only the owner can invite or remove others; owner grant cannot be revoked', async () => {
  const { revokeAdmin } = await import('../services/org-key-admins');
  await expect(inviteAdmin(prisma, invitee, 'org-key', { accountId: 'owner' })).rejects.toThrow('Forbidden');
  await expect(revokeAdmin(prisma, owner, 'org-key', 'owner-grant')).rejects.toThrow('Forbidden');
  const admin = await prisma.keyGrant.findFirstOrThrow({ where: { keyId: 'org-key', granteeUserId: 'invitee', acceptedAt: { not: null } } });
  const challenge = challengeOf(await revokeAdmin(prisma, owner, 'org-key', admin.id));
  const proof = { nonce: challenge.nonce, assertion: assertionFor(ownerPasskey, challenge.challenge, { counter: 2, origin, rpID: owner.rpId }) };
  await revokeAdmin(prisma, owner, 'org-key', admin.id, proof);
  await revokeAdmin(prisma, owner, 'org-key', admin.id, proof);
  expect((await prisma.keyGrant.findUniqueOrThrow({ where: { id: admin.id } })).revokedAt).not.toBeNull();
  expect(await prisma.keyGrantEvent.count({ where: { grantId: admin.id, kind: 'remove' } })).toBe(1);
});

test('email target needs verified matching account and reuses the same normal personal identity', async () => {
  await prisma.keyGrant.create({ data: { id: 'email-match', keyId: 'org-key', role: 'ADMIN', invitedEmail: 'invitee@example.test', invitationExpiresAt: new Date(Date.now() + 60000) } });
  await prisma.user.update({ where: { id: 'invitee' }, data: { emailVerified: false } });
  await expect(acceptAdmin(prisma, invitee, 'email-match')).rejects.toThrow('Forbidden');
  await prisma.user.update({ where: { id: 'invitee' }, data: { emailVerified: true, email: 'other@example.test' } });
  await expect(acceptAdmin(prisma, invitee, 'email-match')).rejects.toThrow('Forbidden');
  await prisma.user.update({ where: { id: 'invitee' }, data: { email: 'INVITEE@example.test' } });
  const challenge = challengeOf(await acceptAdmin(prisma, invitee, 'email-match'));
  const result = await acceptAdmin(prisma, invitee, 'email-match', { nonce: challenge.nonce, assertion: assertionFor(inviteePasskey, challenge.challenge, { counter: 2, origin, rpID: invitee.rpId }) });
  expect(result).toEqual({ keyId: 'org-key' });
  expect((await prisma.keyGrant.findUniqueOrThrow({ where: { id: 'email-match' } })).granteeDid).toBe('did:pkh:eip155:1:0x52908400098527886E0F7030069857D2E4169EE7');
});

test('audit failure rolls acceptance and nonce consumption back together', async () => {
  await prisma.user.create({ data: { id: 'audit-person', email: 'audit@example.test', emailVerified: true } });
  await prisma.session.create({ data: { id: 'audit-session', userId: 'audit-person', token: 'audit-token', expiresAt: new Date(Date.now() + 60000) } });
  await prisma.ethereumKey.create({ data: { id: 'audit-key', userId: 'audit-person', address: '0x0000000000000000000000000000000000000003', publicKey: 'audit', custody: 'PERSONAL', keyType: 'MANAGED', isCanonicalTinyCloud: true } });
  const passkeys = { passkeys: [] as Record<string, unknown>[] };
  const passkey = addPasskey(passkeys, 'audit-person');
  await prisma.passkey.create({ data: { ...passkeys.passkeys[0], id: 'audit-passkey', deviceType: 'singleDevice', backedUp: false } as never });
  await prisma.keyGrant.create({ data: { id: 'audit-failure', keyId: 'org-key', role: 'ADMIN', invitedUserId: 'audit-person', invitationExpiresAt: new Date(Date.now() + 60000) } });
  const actor = { ...invitee, userId: 'audit-person', sessionId: 'audit-session' };
  const challenge = challengeOf(await acceptAdmin(prisma, actor, 'audit-failure'));
  await db.exec(`CREATE FUNCTION fail_audit_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit insert failure'; END; $$;
    CREATE TRIGGER fail_audit BEFORE INSERT ON key_grant_events FOR EACH ROW EXECUTE FUNCTION fail_audit_insert();`);
  try {
    await expect(acceptAdmin(prisma, actor, 'audit-failure', { nonce: challenge.nonce, assertion: assertionFor(passkey, challenge.challenge, { origin, rpID: actor.rpId }) })).rejects.toThrow();
  } finally { await db.exec('DROP TRIGGER fail_audit ON key_grant_events; DROP FUNCTION fail_audit_insert();'); }
  expect((await prisma.keyGrant.findUniqueOrThrow({ where: { id: 'audit-failure' } })).acceptedAt).toBeNull();
  expect((await prisma.orgKeyGrantChallenge.findUniqueOrThrow({ where: { nonce: challenge.nonce } })).consumedAt).toBeNull();
});

test('public invite and accept routes perform the database/passkey flow and reject bearer/foreign-origin calls', async () => {
  const { Hono } = await import('hono');
  const { createMiddleware } = await import('hono/factory');
  const { createOrgKeyAdminsRouter, createOrgKeyInvitationsRouter } = await import('../routes/org-key-admins');
  const original = process.env.ORG_KEY_CUSTODY_ENABLED;
  process.env.ORG_KEY_CUSTODY_ENABLED = 'true';
  await prisma.user.create({ data: { id: 'api-person', email: 'api@example.test', emailVerified: true } });
  await prisma.session.create({ data: { id: 'api-session', userId: 'api-person', token: 'api-token', expiresAt: new Date(Date.now() + 60000) } });
  await prisma.ethereumKey.create({ data: { id: 'api-key', userId: 'api-person', address: '0x0000000000000000000000000000000000000004', publicKey: 'api', custody: 'PERSONAL', keyType: 'MANAGED', isCanonicalTinyCloud: true } });
  const passkeys = { passkeys: [] as Record<string, unknown>[] };
  const passkey = addPasskey(passkeys, 'api-person');
  await prisma.passkey.create({ data: { ...passkeys.passkeys[0], id: 'api-passkey', deviceType: 'singleDevice', backedUp: false } as never });
  let acting = owner;
  const sessionMiddleware = createMiddleware<import('../middleware/session').SessionContext>(async (c, next) => {
    c.set('user', { id: acting.userId, email: 'unused@example.test' });
    c.set('session', { id: acting.sessionId, userId: acting.userId, expiresAt: new Date(Date.now() + 60000) });
    await next();
  });
  const deps = { prisma, sessionMiddleware, webauthn: () => ({ rpID: owner.rpId, origin }) };
  const app = new Hono().route('/api/org-keys', createOrgKeyAdminsRouter(deps)).route('/api/org-key-invitations', createOrgKeyInvitationsRouter(deps));
  const post = (path: string, value: unknown, headers = {}) => app.request(path, { method: 'POST', headers: { origin, 'content-type': 'application/json', ...headers }, body: JSON.stringify(value) });
  try {
    const path = '/api/org-keys/org-key/admin-invitations';
    expect((await post(`${path}/challenge`, { accountId: 'api-person' }, { authorization: 'Bearer token' })).status).toBe(403);
    expect((await post(`${path}/challenge`, { accountId: 'api-person' }, { origin: 'https://foreign.test' })).status).toBe(403);
    const challengeResponse = await post(`${path}/challenge`, { accountId: 'api-person' });
    expect(challengeResponse.status).toBe(200);
    const inviteChallenge = challengeOf(await challengeResponse.json());
    const invited = await post(path, { accountId: 'api-person', nonce: inviteChallenge.nonce, assertion: assertionFor(ownerPasskey, inviteChallenge.challenge, { counter: 3, origin, rpID: owner.rpId }) });
    expect(invited.status).toBe(200);
    const { invitationId } = await invited.json() as { invitationId: string };
    acting = { ...owner, userId: 'api-person', sessionId: 'api-session' };
    const acceptPath = `/api/org-key-invitations/${invitationId}`;
    const acceptChallenge = challengeOf(await (await post(`${acceptPath}/accept-challenge`, {})).json());
    const accepted = await post(`${acceptPath}/accept`, { nonce: acceptChallenge.nonce, assertion: assertionFor(passkey, acceptChallenge.challenge, { origin, rpID: owner.rpId }) });
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toEqual({ keyId: 'org-key' });
    process.env.ORG_KEY_CUSTODY_ENABLED = 'false';
    expect((await app.request('/api/org-keys/org-key/admins')).status).toBe(404);
    expect((await post(`${acceptPath}/accept-challenge`, {})).status).toBe(404);
  } finally {
    if (original === undefined) delete process.env.ORG_KEY_CUSTODY_ENABLED;
    else process.env.ORG_KEY_CUSTODY_ENABLED = original;
  }
});

test.skipIf(!pool)('concurrent exact acceptance retries activate only once on real Postgres', async () => {
  await prisma.user.create({ data: { id: 'race-person', email: 'race@example.test', emailVerified: true } });
  await prisma.session.create({ data: { id: 'race-session', userId: 'race-person', token: 'race-token', expiresAt: new Date(Date.now() + 60000) } });
  await prisma.ethereumKey.create({ data: { id: 'race-key', userId: 'race-person', address: '0x0000000000000000000000000000000000000005', publicKey: 'race', custody: 'PERSONAL', keyType: 'MANAGED', isCanonicalTinyCloud: true } });
  const passkeys = { passkeys: [] as Record<string, unknown>[] };
  const passkey = addPasskey(passkeys, 'race-person');
  await prisma.passkey.create({ data: { ...passkeys.passkeys[0], id: 'race-passkey', deviceType: 'singleDevice', backedUp: false } as never });
  await prisma.keyGrant.create({ data: { id: 'race-invite', keyId: 'org-key', role: 'ADMIN', invitedUserId: 'race-person', invitationExpiresAt: new Date(Date.now() + 60000) } });
  const actor = { ...owner, userId: 'race-person', sessionId: 'race-session' };
  const challenge = challengeOf(await acceptAdmin(prisma, actor, 'race-invite'));
  const proof = { nonce: challenge.nonce, assertion: assertionFor(passkey, challenge.challenge, { origin, rpID: actor.rpId }) };
  expect(await Promise.all([acceptAdmin(prisma, actor, 'race-invite', proof), acceptAdmin(prisma, actor, 'race-invite', proof)])).toEqual([{ keyId: 'org-key' }, { keyId: 'org-key' }]);
  expect(await prisma.keyGrantEvent.count({ where: { grantId: 'race-invite', kind: 'accepted' } })).toBe(1);
  await prisma.keyGrant.update({ where: { id: 'race-invite' }, data: { revokedAt: new Date() } });
  await prisma.keyGrant.create({ data: { id: 'race-cancel', keyId: 'org-key', role: 'ADMIN', invitedUserId: 'race-person', invitationExpiresAt: new Date(Date.now() + 60000) } });
  const next = challengeOf(await acceptAdmin(prisma, actor, 'race-cancel'));
  const nextProof = { nonce: next.nonce, assertion: assertionFor(passkey, next.challenge, { counter: 2, origin, rpID: actor.rpId }) };
  let release!: () => void;
  let held!: () => void;
  const hold = new Promise<void>(resolve => { release = resolve; });
  const locked = new Promise<void>(resolve => { held = resolve; });
  const revoking = prisma.$transaction(async tx => {
    await tx.$queryRaw`SELECT id FROM "ethereum_keys" WHERE id = ${'org-key'} FOR UPDATE`;
    await tx.keyGrant.update({ where: { id: 'race-cancel' }, data: { revokedAt: new Date() } });
    await tx.keyGrantEvent.create({ data: { keyId: 'org-key', grantId: 'race-cancel', actorUserId: 'owner', kind: 'cancel' } });
    held();
    await hold;
  });
  await locked;
  const accepting = acceptAdmin(prisma, actor, 'race-cancel', nextProof).then(() => null, error => error);
  let waiting = false;
  try {
    for (let attempt = 0; attempt < 100; attempt++) {
      const result = await pool!.query("SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'");
      if (result.rowCount) { waiting = true; break; }
      await Bun.sleep(10);
    }
    expect(waiting).toBe(true);
  } finally { release(); }
  await revoking;
  expect(await accepting).toMatchObject({ status: 403 });
  expect((await prisma.keyGrant.findUniqueOrThrow({ where: { id: 'race-cancel' } })).acceptedAt).toBeNull();

});

test('email delivery is attempted once after creation and a failure leaves a usable pending invitation', async () => {
  const mail: { token: string; invitationId: string }[] = [];
  const challenge = challengeOf(await inviteAdmin(prisma, owner, 'org-key', { email: 'delivery@example.test' }));
  const proof = { nonce: challenge.nonce, assertion: assertionFor(ownerPasskey, challenge.challenge, { counter: 4, origin, rpID: owner.rpId }) };
  const deliver = async (value: { token: string; invitationId: string }) => { mail.push(value); };
  const result = await inviteAdmin(prisma, owner, 'org-key', { email: 'delivery@example.test' }, proof, deliver);
  await inviteAdmin(prisma, owner, 'org-key', { email: 'delivery@example.test' }, proof, deliver);
  expect(mail).toHaveLength(1);
  expect(mail[0]!.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(JSON.stringify(result)).not.toContain(mail[0]!.token);
  const failedChallenge = challengeOf(await inviteAdmin(prisma, owner, 'org-key', { email: 'failed@example.test' }));
  const failed = await inviteAdmin(prisma, owner, 'org-key', { email: 'failed@example.test' }, {
    nonce: failedChallenge.nonce, assertion: assertionFor(ownerPasskey, failedChallenge.challenge, { counter: 5, origin, rpID: owner.rpId }),
  }, async () => { throw new Error('local transport failure'); });
  expect(failed).toMatchObject({ delivery: 'failed' });
  const grant = await prisma.keyGrant.findFirstOrThrow({ where: { invitedEmail: 'failed@example.test', revokedAt: null } });
  expect(grant.acceptedAt).toBeNull();
  expect(await prisma.keyGrantEvent.count({ where: { grantId: grant.id, kind: 'delivery-failed' } })).toBe(1);
});
