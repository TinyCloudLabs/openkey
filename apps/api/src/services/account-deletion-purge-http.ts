import { randomUUID } from 'node:crypto';
import { signDeletionInvocation } from './account-deletion-signing';
import type { DeletionHttpTransport } from './account-deletion-list-http';
import type { RegisteredDeletionHost } from './account-deletion-list';

type PurgeResponse = { purgeId: string; complete: boolean };
export async function requestSpacePurge(
  host: RegisteredDeletionHost,
  privateKey: string,
  spaceId: string,
  operation: { idempotencyKey: string } | { purgeId: string },
  transport: DeletionHttpTransport = fetch,
): Promise<PurgeResponse> {
  const url = new URL(host.url);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Invalid registered host TLS origin');
  if (!/^[a-z0-9-]{1,63}$/.test(host.hostId)) throw new Error('Invalid registered host identity');
  const status = 'purgeId' in operation;
  const key = status ? randomUUID() : operation.idempotencyKey;
  const response = await transport(new URL(status ? '/space/purge/status' : '/space/purge', url).href, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30_000),
    headers: {
      Authorization: signDeletionInvocation(privateKey, { resource: `${spaceId}/space`, action: 'tinycloud.space/delete', idempotencyKey: key }),
      'Idempotency-Key': key, 'Content-Type': 'application/json',
    },
    body: JSON.stringify({ version: 1, space_id: spaceId, ...(status ? { purge_id: operation.purgeId } : {}) }),
  });
  if (response.status !== 200 && (status || response.status !== 202)) throw new Error('Space purge unavailable');
  const result = await response.json() as { version?: unknown; purge_id?: unknown; state?: unknown; accepted_at?: unknown; updated_at?: unknown };
  if (result?.version !== 1 || typeof result.purge_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(result.purge_id) || !['purging', 'complete'].includes(result.state as string) || typeof result.accepted_at !== 'string' || !Number.isFinite(Date.parse(result.accepted_at)) || typeof result.updated_at !== 'string' || !Number.isFinite(Date.parse(result.updated_at)) || (status && result.purge_id !== operation.purgeId)) {
    throw new Error('Space purge not acknowledged');
  }
  return { purgeId: result.purge_id, complete: result.state === 'complete' };
}
