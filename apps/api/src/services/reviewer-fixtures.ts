import { isDeepStrictEqual } from 'node:util';
import { randomUUID } from 'node:crypto';
import { TinyCloudNode } from '@tinycloud/node-sdk';
import { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } from '@openkey/tee';
import type { PrismaClient } from '@openkey/db';
import { createSealingContext } from './key-sealing';
import { lockReviewer, unsetReviewer } from './reviewer-accounts';
import { TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS } from './tinycloud-hosts';
import { logReviewer } from '../log';

export const REVIEWER_FIXTURES = [
  ['xyz.tinycloud.tinyapps.todos/catalog', {
    app: 'todos', title: 'Todos', about: 'Synthetic store-review todos.', created: '2026-11-11',
  }],
  ['xyz.tinycloud.tinyapps.todos/catalog/todo', {
    app: 'todos', kind: 'todo', about: 'Synthetic review item.', shape: 'item',
    states: ['open', 'done'], v: 1, fields: { title: 'text' }, created: '2026-11-11',
  }],
  ['xyz.tinycloud.tinyapps.catalog/todos/entry', {
    v: 1, app: 'todos', id: 'xyz.tinycloud.tinyapps.todos', title: 'Todos',
  }],
  ['xyz.tinycloud.tinyapps.todos/todo/open/store-review-fixture', {
    v: 1, at: '2026-11-11T00:00:00.000Z', data: { title: 'Existing synthetic review fixture' },
  }],
] as const;

export async function provisionReviewer(
  database: PrismaClient,
  store: string,
  config: { clientId: string; nodeHost: string },
  reset: boolean,
) {
  if (!['openai', 'google'].includes(store) || !TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(config.nodeHost)) {
    throw new Error('Reviewer configuration refused');
  }
  const client = await database.oauthClient.findUnique({ where: { clientId: config.clientId } });
  if (!client || client.disabled || !client.scopes?.includes('tinycloud:mcp') || client.redirectUris.length !== 1) {
    throw new Error('Reviewer configuration refused');
  }
  // Invalidate process-memory authority before the durable reset transaction.
  await unsetReviewer(database, store);
  const privateKey = generatePrivateKey();
  const address = getAddressFromPrivateKey(privateKey);
  const sealingContext = createSealingContext();
  const sealedBlob = await seal(privateKey, await createTeeClient().deriveKey(`openkey/key/${sealingContext}`));
  const resource = store === 'openai' ? 'https://mcp.tinycloud.xyz/chatgpt/mcp' : 'https://mcp.tinycloud.xyz/mcp';
  const callbackUri = store === 'openai' ? 'https://mcp.tinycloud.xyz/chatgpt/connect/callback' : 'https://mcp.tinycloud.xyz/connect/callback';
  const spaceId = `tinycloud:pkh:eip155:1:${address}:applications`;
  const binding = await database.$transaction(async (transaction) => {
    const before = await lockReviewer(transaction, store);
    if (before.userId && !reset) throw new Error('Use explicit reset for an existing reviewer');
    if (before.userId) {
      await transaction.ethereumKey.deleteMany({ where: { userId: before.userId } });
      await transaction.user.delete({ where: { id: before.userId } });
      logReviewer('reviewer_admin', 'reset', store, before.spaceId ?? undefined);
    }
    const user = await transaction.user.create({ data: {
      id: randomUUID(), email: before.email, emailVerified: true, reviewerHoldAt: new Date(),
      name: 'App review', autoSignEnabled: false, tinyCloudManageKeyEnabled: false,
    } });
    const key = await transaction.ethereumKey.create({ data: {
      id: randomUUID(), userId: user.id, address, publicKey: address, sealedBlob, sealingContext,
      isCanonicalTinyCloud: true, keyIndex: 0, label: 'App review',
    } });
    return transaction.reviewerAccount.update({ where: { store }, data: {
      userId: user.id, keyId: key.id, spaceId, clientId: config.clientId, redirectUri: client.redirectUris[0],
      resource, callbackUri, nodeHost: config.nodeHost, sessionDid: null, seededAt: null, readyAt: null,
      grantSessionId: null, installEpoch: { increment: 1 },
    } });
  });
  const node = new TinyCloudNode({
    host: config.nodeHost, privateKey, prefix: 'applications', sessionExpirationMs: 3600_000,
    autoCreateSpace: true, autoBootstrapAccount: false, enablePublicSpace: false,
    includeAccountRegistryPermissions: false, autoDiscoverLocalNode: false,
  });
  await node.signIn();
  const hosted = await node.ensureOwnedSpaceHosted('applications');
  if (hosted !== spaceId) throw new Error('Reviewer space mismatch');
  const kv = node.kvForSpace(hosted);
  for (const [path, value] of REVIEWER_FIXTURES) {
    const result = await kv.put(path, value, { ifNoneMatch: '*' });
    const readback = await kv.get(path);
    const matches = readback.ok && isDeepStrictEqual(readback.data.data, value);
    if (!result.ok && !matches) throw new Error('Reviewer fixture write failed');
    if (!matches) throw new Error('Reviewer fixture verification failed');
  }
  const completed = await database.reviewerAccount.updateMany({
    where: { store, userId: binding.userId, installEpoch: binding.installEpoch }, data: { seededAt: new Date() },
  });
  if (completed.count !== 1) throw new Error('Reviewer fixture was superseded');
}
