// TinyCloud service - manages TinyCloud sessions and operations on behalf of users
import { TinyCloudNode } from '@tinycloud/node-sdk';
import { Wallet } from 'ethers';

const TINYCLOUD_URL = process.env.TINYCLOUD_URL || 'https://node.tinycloud.xyz';

interface TinyCloudSession {
  tc: TinyCloudNode;       // prefix: 'openkey' — for KV/variables
  secretsTc: TinyCloudNode; // prefix: 'secrets' — for vault/secrets
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
  const tc = new TinyCloudNode({
    host: TINYCLOUD_URL,
    privateKey,
    prefix: 'openkey',
    autoCreateSpace: true,
  });
  await tc.signIn();

  // Secrets space for vault
  const secretsTc = new TinyCloudNode({
    host: TINYCLOUD_URL,
    privateKey,
    prefix: 'secrets',
    autoCreateSpace: true,
  });
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
      if (getResult.ok && getResult.data?.createdAt) {
        createdAt = getResult.data.createdAt;
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
