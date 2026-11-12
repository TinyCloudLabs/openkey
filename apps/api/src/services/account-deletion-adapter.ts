import { Wallet } from 'ethers';
import type { DeletionAdapter } from './account-deletion-job';
import type { RegisteredDeletionHost } from './account-deletion-list';
import { listOwnerSpacesOverHttp, type DeletionHttpTransport } from './account-deletion-list-http';
import { retireOwnerOverHttp } from './account-deletion-retire-http';
import { requestSpacePurge } from './account-deletion-purge-http';

// Configuration comes from the operator-reviewed operated-host registry.
// This factory does not enable the scheduler's production transport.
export function createDeletionAdapter(
  privateKey: string,
  hosts: RegisteredDeletionHost[],
  recordedHosts: string[],
  transport: DeletionHttpTransport = fetch,
): DeletionAdapter {
  const owner = `did:pkh:eip155:1:${new Wallet(privateKey).address}`;
  const prefix = `tinycloud:${owner.slice(4)}:`;
  const ownedSpace = (space: string) => {
    if (!space.startsWith(prefix) || !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(space.slice(prefix.length))) throw new Error('Invalid owner space');
    return space;
  };
  const registry = new Map(hosts.map(host => [new URL(host.url).origin, host]));
  if (registry.size !== hosts.length || new Set(hosts.map(host => host.hostId)).size !== hosts.length) throw new Error('Duplicate registered host');
  const registered = (url: string) => {
    const host = registry.get(url);
    if (!host) throw new Error('Unregistered deletion host');
    return host;
  };
  return {
    hosts: async () => [...registry.keys()],
    recordedHosts: async () => recordedHosts.map(host => new URL(host).origin),
    retire: (host, key) => retireOwnerOverHttp(registered(host), privateKey, key, transport),
    list: async host => (await listOwnerSpacesOverHttp(registered(host), privateKey, transport)).map(ownedSpace),
    purge: (host, space, key) => requestSpacePurge(registered(host), privateKey, ownedSpace(space), { idempotencyKey: key }, transport),
    status: async (host, space, purgeId) => (await requestSpacePurge(registered(host), privateKey, ownedSpace(space), { purgeId }, transport)).complete,
  };
}
