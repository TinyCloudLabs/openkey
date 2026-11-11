import { appleReviewEnabled, APPLE_REVIEW_CLIENT_ID } from './reviewer-apple-policy';
import { enabledNativeDelegation } from './native-delegation/policy';
import { retireReviewerOwner } from './reviewer-cleanup';
import { TINYCLOUD_BOOTSTRAP_VERSION } from './tinycloud-bootstrap';
import { isDeepStrictEqual } from 'node:util';
import { randomUUID } from 'node:crypto';
import { TinyCloudNode } from '@tinycloud/node-sdk';
import { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } from '@openkey/tee';
import { Prisma, type PrismaClient } from '@openkey/db';
import { createSealingContext } from './key-sealing';
import { lockReviewer, holdReviewer } from './reviewer-accounts';
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
  config: { clientId: string; nodeHost: string; redirectUri?: string },
  reset: boolean,
) {
  if ((!['openai', 'google', 'apple'].includes(store) || (store === 'apple' && !appleReviewEnabled())) || !TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(config.nodeHost)) {
    throw new Error('Reviewer configuration refused');
  }
  const client = await database.oauthClient.findUnique({ where: { clientId: config.clientId } });
  const native = client && enabledNativeDelegation(client);
  const redirectUri = config.redirectUri ?? (client?.redirectUris.length === 1 ? client.redirectUris[0] : undefined);
  if (!client || client.disabled || !redirectUri || !client.redirectUris.includes(redirectUri)
    || (store === 'apple' ? client.clientId !== APPLE_REVIEW_CLIENT_ID || !native || native.tinycloudHost !== config.nodeHost
      : !client.scopes?.includes('tinycloud:mcp') || client.redirectUris.length !== 1)) {
    throw new Error('Reviewer configuration refused');
  }
  const privateKey = generatePrivateKey();
  const address = getAddressFromPrivateKey(privateKey);
  const sealingContext = createSealingContext();
  const sealedBlob = await seal(privateKey, await createTeeClient().deriveKey(`openkey/key/${sealingContext}`));
  const resource = store === 'openai' ? 'https://mcp.tinycloud.xyz/chatgpt/mcp' : 'https://mcp.tinycloud.xyz/mcp';
  const callbackUri = store === 'openai' ? 'https://mcp.tinycloud.xyz/chatgpt/connect/callback' : 'https://mcp.tinycloud.xyz/connect/callback';
  const spaceId = `tinycloud:pkh:eip155:1:${address}:applications`;
  let resetSpace: string | null = null;
  const binding = await database.$transaction(async (transaction) => {
    const before = await lockReviewer(transaction, store);
    if (before.userId && !reset) throw new Error('Use explicit reset for an existing reviewer');
    const held = await holdReviewer(transaction, before);
    if (before.userId) {
      if (store === 'apple') await retireReviewerOwner(transaction, before);
      await transaction.ethereumKey.deleteMany({ where: { userId: before.userId } });
      await transaction.user.delete({ where: { id: before.userId } });
      resetSpace = before.spaceId;
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
      userId: user.id, keyId: key.id, spaceId, clientId: config.clientId, redirectUri,
      resource: store === 'apple' ? null : resource, callbackUri: store === 'apple' ? null : callbackUri, nodeHost: config.nodeHost, sessionDid: null, seededAt: null, readyAt: null,
      grantSessionId: null, installEpoch: held.installEpoch,
      seedRun: Prisma.DbNull, seedStartedAt: null, writerExpiresAt: null,
    } });
  });
  if (resetSpace) logReviewer('reviewer_admin', 'reset', store, resetSpace);
  const node = new TinyCloudNode({
    host: config.nodeHost, privateKey, prefix: 'applications', sessionExpirationMs: 3600_000,
    autoCreateSpace: true, autoBootstrapAccount: false, enablePublicSpace: false,
    includeAccountRegistryPermissions: false, autoDiscoverLocalNode: false,
  });
  await node.signIn();
  const hosted = await node.ensureOwnedSpaceHosted('applications');
  if (hosted !== spaceId) throw new Error('Reviewer space mismatch');
  if (store === 'apple') {
    await database.$transaction(async transaction => {
      const current = await lockReviewer(transaction, store);
      if (current.userId !== binding.userId || current.installEpoch !== binding.installEpoch) throw new Error('Reviewer fixture was superseded');
      await transaction.tinyCloudBootstrapState.create({ data: {
        userId: binding.userId!, keyId: binding.keyId!, address, chainId: 1,
        tinycloudHost: config.nodeHost, bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION,
        status: 'complete', checkedAt: new Date(), completedAt: new Date(),
      } });
    });
    return;
  }
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
