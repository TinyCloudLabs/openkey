import { randomUUID } from 'node:crypto';
import { Wallet } from 'ethers';
import { signDeletionInvocation, type DeletionInvocation } from './account-deletion-signing';
import type { RegisteredDeletionHost } from './account-deletion-list';
import type { DeletionHttpTransport } from './account-deletion-list-http';

export class DeletionNeedsOwnerReview extends Error {
  constructor() { super('Needs owner review'); }
}

export function createResourceDeletionClient(host: RegisteredDeletionHost, privateKey: string, transport: DeletionHttpTransport = fetch) {
  const origin = new URL(host.url);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/' || !/^[a-z0-9-]{1,63}$/.test(host.hostId)) throw new Error('Invalid resource host');
  const owner = `did:pkh:eip155:1:${new Wallet(privateKey).address}`;
  const prefix = `urn:tinycloud:encryption:${owner}:`;
  const exactResource = (resource: string) => {
    if (typeof resource !== 'string' || !resource.startsWith(prefix) || resource.length === prefix.length || resource.endsWith('/') || resource.includes('*') || /[\x00-\x20\x7f]/.test(resource)) throw new Error('Invalid owned resource');
    return resource;
  };
  const request = async (path: string, action: DeletionInvocation['action'], resource: string, body: object, key: string = randomUUID()) => {
    const response = await transport(new URL(path, origin).href, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30_000),
      headers: { Authorization: signDeletionInvocation(privateKey, { resource, action, idempotencyKey: key, hostId: host.hostId }), 'Content-Type': 'application/json', 'Idempotency-Key': key },
      body: JSON.stringify(body),
    });
    const value = await response.json() as Record<string, unknown>;
    if (!value || value.hostId !== host.hostId) throw new Error('Resource host mismatch');
    if (response.status === 409 && (value.error as { code?: unknown } | undefined)?.code === 'dependency_review_required') throw new DeletionNeedsOwnerReview();
    if (![200, 202].includes(response.status)) throw new Error('Resource operation unavailable');
    if (value.version !== 1) throw new Error('Invalid resource response');
    return { value, status: response.status };
  };
  const purge = async (resource: string, operation: { idempotencyKey: string } | { purgeId: string }) => {
    exactResource(resource);
    const status = 'purgeId' in operation;
    const { value, status: httpStatus } = await request(status ? '/resource/purge/status' : '/resource/purge', 'tinycloud.resource/delete', resource,
      { version: 1, resource_id: resource, ...(status ? { purge_id: operation.purgeId } : {}) }, status ? randomUUID() : operation.idempotencyKey);
    if ((status && httpStatus !== 200) || typeof value.purge_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.purge_id) || !['purging', 'complete'].includes(value.state as string) || (status && value.purge_id !== operation.purgeId) || typeof value.accepted_at !== 'string' || !Number.isFinite(Date.parse(value.accepted_at)) || typeof value.updated_at !== 'string' || !Number.isFinite(Date.parse(value.updated_at))) throw new Error('Invalid resource purge response');
    return { purgeId: value.purge_id, complete: value.state === 'complete' };
  };
  return {
    inventory: async (): Promise<string[]> => {
      let cursor: string | null = null;
      const cursors = new Set<string>();
      const resources: string[] = [];
      for (;;) {
        const { value, status } = await request('/resource/list', 'tinycloud.resource/list', owner, { version: 1, ownerDid: owner, cursor });
        if (status !== 200 || value.ownerDid !== owner || !Array.isArray(value.resources) || value.resources.length > 500 || typeof value.lastPage !== 'boolean') throw new Error('Incomplete resource inventory');
        for (const resource of value.resources) {
          exactResource(resource);
          if (resources.length && resource <= resources[resources.length - 1]!) throw new Error('Invalid resource ordering');
          resources.push(resource);
        }
        if (value.lastPage) {
          if (value.nextCursor !== null) throw new Error('Invalid terminal resource page');
          return resources;
        }
        if (typeof value.nextCursor !== 'string' || !value.nextCursor || cursors.has(value.nextCursor)) throw new Error('Incomplete resource pages');
        cursors.add(value.nextCursor);
        cursor = value.nextCursor;
      }
    },
    dependencies: async () => {
      const { value, status } = await request('/resource/dependencies', 'tinycloud.resource/dependencies', owner, { version: 1, ownerDid: owner });
      if (status !== 200 || typeof value.ownerHmac !== 'string' || !/^[0-9a-f]{64}$/i.test(value.ownerHmac) || !Number.isSafeInteger(value.dependentResourceCount) || (value.dependentResourceCount as number) < 0) throw new Error('Invalid dependency snapshot');
      return { ownerHmac: value.ownerHmac, count: value.dependentResourceCount as number };
    },
    purge: (resource: string, key: string) => purge(resource, { idempotencyKey: key }),
    status: (resource: string, purgeId: string) => purge(resource, { purgeId }),
  };
}
