import { describe, expect, test } from 'bun:test';
import {
  changeTinyCloudManageKeyGrant,
  changeTinyCloudManageKeyMode,
  withTinyCloudManageKeySigningPolicy,
} from '../services/tinycloud-manage-key-control';

function controlDatabase() {
  const user = {
    id: 'user_1',
    tinyCloudManageKeyEnabled: true,
    tinyCloudManageKeyMode: 'APP_MANAGED',
    tinyCloudManageKeyPolicyEpoch: BigInt(0),
  };
  const grants = new Map<string, { enabled: boolean; status: string }>();
  const events: any[] = [];
  const decisions: any[] = [];
  const db: any = {
    $transaction: async (callback: (tx: any) => Promise<unknown>) => callback(db),
    $queryRawUnsafe: async () => [],
    user: {
      findUnique: async () => ({ ...user }),
      updateMany: async ({ where, data }: any) => {
        if (where.tinyCloudManageKeyPolicyEpoch !== user.tinyCloudManageKeyPolicyEpoch) return { count: 0 };
        user.tinyCloudManageKeyMode = data.tinyCloudManageKeyMode ?? user.tinyCloudManageKeyMode;
        user.tinyCloudManageKeyEnabled = data.tinyCloudManageKeyEnabled ?? user.tinyCloudManageKeyEnabled;
        if (data.tinyCloudManageKeyPolicyEpoch?.increment) user.tinyCloudManageKeyPolicyEpoch += BigInt(data.tinyCloudManageKeyPolicyEpoch.increment);
        return { count: 1 };
      },
    },
    oauthConsent: { findFirst: async () => ({ clientId: 'client_1' }) },
    oauthClient: { findUnique: async () => ({ name: 'Client One', uri: 'https://client.example' }) },
    tinyCloudManageKeyAppPreference: {
      findUnique: async ({ where }: any) => grants.get(where.userId_clientId.clientId) ?? null,
      upsert: async ({ where, create, update }: any) => {
        const next = grants.has(where.userId_clientId.clientId) ? update : create;
        const grant = { enabled: next.enabled, status: next.status };
        grants.set(where.userId_clientId.clientId, grant);
        return grant;
      },
      updateMany: async ({ data }: any) => {
        for (const [clientId, grant] of grants) grants.set(clientId, { ...grant, enabled: data.enabled, status: data.status });
        return { count: grants.size };
      },
    },
    tinyCloudManageKeyControlEvent: { create: async ({ data }: any) => (events.push(data), data) },
    tinyCloudManageKeySigningDecision: { create: async ({ data }: any) => (decisions.push(data), data) },
  };
  return { db, user, grants, events, decisions };
}

describe('TinyCloud manage-key lifecycle controls', () => {
  test('user control is one-way, shared requires a grant, and exclusive fails closed', async () => {
    const { db, user, events, decisions } = controlDatabase();
    const deniedInShared = await changeTinyCloudManageKeyMode(db, user.id, {
      mode: 'USER_CONTROLLED_SHARED', expectedEpoch: 0, request: { mode: 'USER_CONTROLLED_SHARED' },
    });
    expect(deniedInShared).toMatchObject({ kind: 'changed', epoch: 1 });
    expect(await withTinyCloudManageKeySigningPolicy(db, { userId: user.id, clientId: 'client_1', request: { request: 1 } }, async () => 'signed')).toEqual({ allowed: false, reason: 'policy_denied' });

    const granted = await changeTinyCloudManageKeyGrant(db, user.id, 'client_1', {
      enabled: true, expectedEpoch: 1, request: { enabled: true },
    });
    expect(granted).toMatchObject({ kind: 'changed', epoch: 2 });
    expect(await withTinyCloudManageKeySigningPolicy(db, { userId: user.id, clientId: 'client_1', request: { request: 2 } }, async () => 'signed')).toEqual({ allowed: true, value: 'signed' });

    const exclusive = await changeTinyCloudManageKeyMode(db, user.id, {
      mode: 'USER_CONTROLLED_EXCLUSIVE', expectedEpoch: 2, request: { mode: 'USER_CONTROLLED_EXCLUSIVE' },
    });
    expect(exclusive).toMatchObject({ kind: 'changed', epoch: 3 });
    expect(await withTinyCloudManageKeySigningPolicy(db, { userId: user.id, clientId: 'client_1', request: { request: 3 } }, async () => 'signed')).toEqual({ allowed: false, reason: 'policy_denied' });

    const invalidReturn = await changeTinyCloudManageKeyMode(db, user.id, {
      mode: 'APP_MANAGED', expectedEpoch: 3, request: { mode: 'APP_MANAGED' },
    });
    expect(invalidReturn).toMatchObject({ kind: 'invalid_transition', epoch: 3 });
    expect(events).toHaveLength(3);
    expect(decisions.map((decision) => decision.allowed)).toEqual([false, true, false]);
  });

  test('an explicit re-enable is idempotent and only takes effect after shared control resumes', async () => {
    const { db, user, events } = controlDatabase();
    await changeTinyCloudManageKeyMode(db, user.id, { mode: 'USER_CONTROLLED_EXCLUSIVE', expectedEpoch: 0, request: { mode: 'USER_CONTROLLED_EXCLUSIVE' } });
    const enabled = await changeTinyCloudManageKeyGrant(db, user.id, 'client_1', { enabled: true, expectedEpoch: 1, request: { enabled: true } });
    expect(enabled).toMatchObject({ kind: 'changed', epoch: 2 });
    const replay = await changeTinyCloudManageKeyGrant(db, user.id, 'client_1', { enabled: true, expectedEpoch: 2, request: { enabled: true } });
    expect(replay).toMatchObject({ kind: 'unchanged', epoch: 2 });
    expect(events).toHaveLength(2);
    expect(await withTinyCloudManageKeySigningPolicy(db, { userId: user.id, clientId: 'client_1', request: { request: 'exclusive' } }, async () => 'signed')).toEqual({ allowed: false, reason: 'policy_denied' });
    await changeTinyCloudManageKeyMode(db, user.id, { mode: 'USER_CONTROLLED_SHARED', expectedEpoch: 2, request: { mode: 'USER_CONTROLLED_SHARED' } });
    expect(await withTinyCloudManageKeySigningPolicy(db, { userId: user.id, clientId: 'client_1', request: { request: 'shared' } }, async () => 'signed')).toEqual({ allowed: true, value: 'signed' });
  });
});
