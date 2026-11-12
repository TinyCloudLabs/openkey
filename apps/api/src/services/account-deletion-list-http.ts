import { randomUUID } from 'node:crypto';
import { Wallet } from 'ethers';
import { listAllDeletionSpaces, type RegisteredDeletionHost, type OwnerSpacePage } from './account-deletion-list';
import { signDeletionInvocation } from './account-deletion-signing';

export type DeletionHttpTransport = (url: string, options: RequestInit) => Promise<Response>;

// Called only with the deletion worker's retained owner key. Never signs in
// through node-sdk, which would create a delegated session or owner space.
export async function listOwnerSpacesOverHttp(
  host: RegisteredDeletionHost,
  privateKey: string,
  transport: DeletionHttpTransport = fetch,
): Promise<string[]> {
  const ownerDid = `did:pkh:eip155:1:${new Wallet(privateKey).address}`;
  return listAllDeletionSpaces(host, ownerDid, async (url, body) => {
    const idempotencyKey = randomUUID();
    const invocation = signDeletionInvocation(privateKey, { resource: ownerDid, action: 'tinycloud.space/list', idempotencyKey });
    const response = await transport(url, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30_000),
      headers: { Authorization: invocation, 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(body),
    });
    if (response.status !== 200) throw new Error('Owner space listing unavailable');
    return await response.json() as OwnerSpacePage;
  });
}
