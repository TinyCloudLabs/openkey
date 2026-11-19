// TinyCloud service - manages TinyCloud sessions and operations on behalf of users
import { TinyCloudNode } from '@tinycloud/node-sdk';
import { SECRETS_SPACE } from '@tinycloud/bootstrap';
import { Wallet } from 'ethers';

// The production node answers at both node.tinycloud.xyz and tee.node.tinycloud.xyz; OpenKey's own sessions use
// tee.node. Bootstrap state is keyed by TINYCLOUD_BOOTSTRAP_HOST instead (tinycloud-hosts.ts), which stays node.*.
const TINYCLOUD_URL = process.env.TINYCLOUD_URL || 'https://tee.node.tinycloud.xyz';
export const OPENKEY_LEGACY_SPACE = 'openkey';

// node-sdk >= 2.11 adds the `account` registry space (kv, sql, delegation/list,
// capabilities) to the sign-in SIWE unless this is false. These sessions only
// need their own space, so keep the recap OpenKey's managed key signs narrow.
//
// `autoBootstrapAccount: false` (TC-3115): the SDK would otherwise run a full account bootstrap inside every
// `signIn()`: it hosts and activates six spaces one request at a time, then tries to create the account index in
// the `account` space, which these narrow sessions cannot write (401), so it aborts and does it all again at the next
// sign-in. Measured against the production node it costs about 8 to 9 s per sign-in, 17 to 20 s for the two sessions
// of one /api/secrets/enable, and ends in a gateway 502. OpenKey provisions the account itself
// (services/tinycloud-bootstrap.ts), as the SDK expects of a server-side signer. The option is read at runtime but
// missing from the published type.
export function createSessionNode(privateKey: string, prefix: string): TinyCloudNode {
  return new TinyCloudNode({
    host: TINYCLOUD_URL,
    privateKey,
    prefix,
    autoCreateSpace: true,
    includeAccountRegistryPermissions: false,
    ...({ autoBootstrapAccount: false } as object),
  });
}

interface TinyCloudSession {
  tc: TinyCloudNode;       // legacy OpenKey-internal space for KV/variables
  secretsTc: TinyCloudNode; // canonical bootstrap secrets space for vault/secrets
  wallet: Wallet;
}

// In-memory cache of TinyCloud sessions per userId
const sessions = new Map<string, TinyCloudSession>();

async function getSession(userId: string, privateKey: string): Promise<TinyCloudSession> {
  const existing = sessions.get(userId);
  if (existing) {
    return existing;
  }

  const wallet = new Wallet(`0x${privateKey}`);

  // Main space for variables/KV
  const tc = createSessionNode(privateKey, OPENKEY_LEGACY_SPACE);
  await tc.signIn();

  // Secrets space for vault
  const secretsTc = createSessionNode(privateKey, SECRETS_SPACE);
  await secretsTc.signIn();
  await secretsTc.vault.unlock(wallet);

  const session: TinyCloudSession = { tc, secretsTc, wallet };
  sessions.set(userId, session);
  return session;
}

export class TinyCloudService {
  async enableForUser(userId: string, privateKey: string): Promise<{ spaceId: string }> {
    const session = await getSession(userId, privateKey);
    return { spaceId: session.tc.spaceId! };
  }

  async isEnabledForUser(userId: string): Promise<boolean> {
    return sessions.has(userId);
  }

  // =========================================================================
  // Secrets (vault - encrypted)
  // =========================================================================

  async putSecret(userId: string, name: string, value: string): Promise<{ createdAt: string }> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const createdAt = new Date().toISOString();
    const result = await session.secretsTc.vault.put(`secrets/${name}`, { value, createdAt });
    if (!result.ok) {
      throw new Error(`Failed to store secret: ${(result as any).error?.message}`);
    }
    return { createdAt };
  }

  async listSecrets(userId: string): Promise<Array<{ name: string; createdAt: string }>> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const listResult = await session.secretsTc.vault.list({ prefix: 'secrets/' });
    if (!listResult.ok) {
      throw new Error(`Failed to list secrets: ${(listResult as any).error?.message}`);
    }

    const secrets: Array<{ name: string; createdAt: string }> = [];
    for (const key of listResult.data) {
      const name = key.replace('secrets/', '');
      let createdAt = '';
      // Read the stored payload to get createdAt
      const getResult = await session.secretsTc.vault.get<{ value: string; createdAt: string }>(key);
      if (getResult.ok && getResult.data?.value.createdAt) {
        createdAt = getResult.data.value.createdAt;
      }
      secrets.push({ name, createdAt });
    }

    return secrets;
  }

  async deleteSecret(userId: string, name: string): Promise<void> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const result = await session.secretsTc.vault.delete(`secrets/${name}`);
    if (!result.ok) {
      throw new Error(`Failed to delete secret: ${(result as any).error?.message}`);
    }
  }

  // =========================================================================
  // Variables (KV - plaintext)
  // =========================================================================

  async putVariable(userId: string, name: string, value: string): Promise<{ createdAt: string }> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const createdAt = new Date().toISOString();
    const kv = session.tc.kv.withPrefix('variables/');
    const result = await kv.put(name, { value, createdAt });
    if (!result.ok) {
      throw new Error(`Failed to store variable: ${(result as any).error?.message}`);
    }
    return { createdAt };
  }

  async getVariable(userId: string, name: string): Promise<{ value: string; createdAt: string }> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const kv = session.tc.kv.withPrefix('variables/');
    const result = await kv.get<{ value: string; createdAt: string }>(name);
    if (!result.ok) {
      throw new Error(`Failed to get variable: ${(result as any).error?.message}`);
    }
    return result.data.data as { value: string; createdAt: string };
  }

  async listVariables(userId: string): Promise<Array<{ name: string; value: string; createdAt: string }>> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const kv = session.tc.kv.withPrefix('variables/');
    const listResult = await kv.list();
    if (!listResult.ok) {
      throw new Error(`Failed to list variables: ${(listResult as any).error?.message}`);
    }

    const variables: Array<{ name: string; value: string; createdAt: string }> = [];
    for (const key of listResult.data.keys) {
      const getResult = await kv.get<{ value: string; createdAt: string }>(key);
      if (getResult.ok && getResult.data.data) {
        const data = getResult.data.data as { value: string; createdAt: string };
        variables.push({ name: key, value: data.value, createdAt: data.createdAt });
      }
    }

    return variables;
  }

  async deleteVariable(userId: string, name: string): Promise<void> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const kv = session.tc.kv.withPrefix('variables/');
    const result = await kv.delete(name);
    if (!result.ok) {
      throw new Error(`Failed to delete variable: ${(result as any).error?.message}`);
    }
  }
}

export const tinyCloudService = new TinyCloudService();
