import { Wallet } from 'ethers';
import { signDeletionInvocation } from './account-deletion-signing';
import type { DeletionHttpTransport } from './account-deletion-list-http';
import type { RegisteredDeletionHost } from './account-deletion-list';

export async function retireOwnerOverHttp(
  host: RegisteredDeletionHost,
  privateKey: string,
  idempotencyKey: string,
  transport: DeletionHttpTransport = fetch,
): Promise<void> {
  const url = new URL(host.url);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Invalid registered host TLS origin');
  if (!/^[a-z0-9-]{1,63}$/.test(host.hostId)) throw new Error('Invalid registered host identity');
  const owner = `did:pkh:eip155:1:${new Wallet(privateKey).address}`;
  const response = await transport(new URL('/space/retire-owner', url).href, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30_000),
    headers: {
      Authorization: signDeletionInvocation(privateKey, { resource: owner, action: 'tinycloud.space/retire-owner', idempotencyKey, hostId: host.hostId }),
      'Idempotency-Key': idempotencyKey, 'Content-Type': 'application/json',
    },
    body: JSON.stringify({ version: 1, owner_did: owner }),
  });
  if (response.status !== 200 && response.status !== 202) throw new Error('Owner retirement unavailable');
  const acknowledgement = await response.json() as { hostId?: unknown; version?: unknown; state?: unknown };
  if (acknowledgement?.hostId !== host.hostId || acknowledgement.version !== 1 || acknowledgement.state !== 'retired') throw new Error('Owner retirement not acknowledged');
}
