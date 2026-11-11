import { TinyCloudNode } from '@tinycloud/node-sdk';
import type { ReviewerCleanupAdapter } from './reviewer-cleanup';
import { buildReviewerGrant } from './reviewer-apple-seed';
import { REVIEWER_HOME_PERMISSIONS } from './reviewer-apple-policy';
import { TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS } from './tinycloud-hosts';

// Only this module can mint or consume a cleanup session. No caller can obtain
// its key, grant, services or a general-purpose signing callback.
const sql = REVIEWER_HOME_PERMISSIONS.filter(p => p.service === 'tinycloud.sql');
const permissions = [
  { service: 'tinycloud.kv', space: 'applications', path: '', actions: ['tinycloud.kv/list', 'tinycloud.kv/get', 'tinycloud.kv/del'] },
  ...sql.map(p => ({ service: p.service, space: 'applications', path: p.path, actions: ['tinycloud.sql/schema', 'tinycloud.sql/read', 'tinycloud.sql/write'] })),
];
const identifier = (value: string) => '"' + value.replaceAll('"', '""') + '"';

export const reviewerCleanupNode: ReviewerCleanupAdapter = {
  async wipe(row) {
    if (!row.sealedBlob || !TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(row.nodeHost)
      || row.spaceId !== `tinycloud:pkh:eip155:1:${row.address}:applications`) throw new Error('Cleanup target refused');
    const expiresAt = new Date(Date.now() + 45_000);
    const node = new TinyCloudNode({ host: row.nodeHost, autoCreateSpace: false,
      autoBootstrapAccount: false, enablePublicSpace: false, includeAccountRegistryPermissions: false, autoDiscoverLocalNode: false });
    if (!node.isSessionOnly) throw new Error('Cleanup authority refused');
    const { delegation: grant } = await buildReviewerGrant({ ...row, userId: row.ownerUserId, sealedBlob: row.sealedBlob },
      row.spaceId, row.nodeHost, node.did.split('#')[0]!, permissions, expiresAt);
    const activation = await fetch(row.nodeHost + '/delegate', { method: 'POST', headers: grant.delegationHeader,
      redirect: 'error', signal: AbortSignal.timeout(5_000) });
    if (!activation.ok) throw new Error('Cleanup activation failed');
    const activated = await activation.json() as { activated?: string[]; skipped?: string[] };
    if (!activated.activated?.includes(row.spaceId)
      && !(activated.activated?.length === 0 && activated.skipped?.length === 0)) throw new Error('Cleanup activation refused');
    const access = await node.useDelegation(grant);
    if (access.spaceId !== row.spaceId) throw new Error('Cleanup space refused');
    const signal = AbortSignal.timeout(40_000);
    // Start at the beginning after deleting each page, so changing keys never
    // causes an offset cursor to skip data. Unknown pagination fails closed.
    for (let page = 0; page < 100; page++) {
      const result = await access.kv.list({ prefix: '', limit: 100, signal });
      if (!result.ok || !Array.isArray(result.data.keys)) throw new Error('Cleanup list failed');
      if (!result.data.keys.length) {
        if (result.data.truncated || result.data.nextCursor) throw new Error('Cleanup list incomplete');
        break;
      }
      for (const key of result.data.keys) {
        if (typeof key !== 'string') throw new Error('Cleanup key refused');
        const deleted = await access.kv.delete(key, { prefix: '', signal });
        if (!deleted.ok) throw new Error('Cleanup delete failed');
      }
      if (page === 99) throw new Error('Cleanup budget exceeded');
    }
    // Best effort over the named DBs, including both fixed seed feed DBs.
    // The prefix may also contain unknown DBs; TC-2817 is required before
    // empty() can ever attest completeness or allow destruction of the key.
    const names = [...sql.filter(p => !p.path.endsWith('/')).map(p => p.path),
      'xyz.tinycloud.tinychat/feed/feed_output_home_tour', 'xyz.tinycloud.tinychat/feed/feed_responses_home_tour'];
    for (const name of names) {
      const db = access.sql.db(name);
      const tables = await db.query<string>("SELECT type, name FROM sqlite_schema WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type DESC", [], { signal, maxRows: 513 });
      if (!tables.ok || tables.data.rows.length > 512) throw new Error('Cleanup SQL inspection failed');
      for (const [type, name] of tables.data.rows) {
        if (typeof type !== 'string' || !['table', 'view'].includes(type) || typeof name !== 'string') throw new Error('Cleanup SQL name refused');
        const dropped = await db.execute(`DROP ${type.toUpperCase()} IF EXISTS ${identifier(name)}`, [], { signal });
        if (!dropped.ok) throw new Error('Cleanup SQL drop failed');
      }
    }
  },
  async empty() {
    // No complete SQL enumeration exists on the current node API. Keep the
    // sealed cleanup key and alert (TC-2817); fixed seed DBs are not proof.
    return false;
  },
};
