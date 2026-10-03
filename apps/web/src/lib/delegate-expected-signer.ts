/**
 * The account a `/delegate` request names:
 * - `owner`: every permission resolves to one `did:pkh:eip155:<chainId>:<address>`
 *   owner (address lowercase), so the UI pins that wallet;
 * - `conflict`: every permission resolves to an owner, but they differ (in
 *   address or chain); OpenKey cannot sign such a request for any wallet;
 * - `none`: some permission names no pkh owner (a short space name, or a
 *   malformed entry), so nothing is pinned.
 */
export type ExpectedSigner =
  | { kind: 'none' }
  | { kind: 'owner'; chainId: string; address: string }
  | { kind: 'conflict'; owners: string[] };

const SPACE_OWNER = /^tinycloud:pkh:eip155:(\d+):(0x[a-fA-F0-9]{40}):/;
const RAW_ENCRYPTION_OWNER = /^urn:tinycloud:encryption:did:pkh:eip155:(\d+):(0x[a-fA-F0-9]{40}):/;

/**
 * Resolve each permission's owner: a space permission through its
 * `tinycloud:pkh:eip155:<chain>:<addr>:<name>` space URI, a raw encryption
 * network through its `urn:tinycloud:encryption:did:pkh:eip155:<chain>:<addr>:<name>`
 * owner DID.
 */
export function expectedSigner(permissions: readonly unknown[]): ExpectedSigner {
  if (permissions.length === 0) return { kind: 'none' };
  const owners = new Map<string, { chainId: string; address: string }>();
  for (const permission of permissions) {
    if (!permission || typeof permission !== 'object') return { kind: 'none' };
    const { service, space, path } = permission as Record<string, unknown>;
    if (typeof service !== 'string' || typeof path !== 'string') return { kind: 'none' };
    const isRawEncryption =
      (service === 'tinycloud.encryption' || service === 'encryption') &&
      path.startsWith('urn:tinycloud:encryption:');
    const owner = isRawEncryption
      ? RAW_ENCRYPTION_OWNER.exec(path)
      : typeof space === 'string' ? SPACE_OWNER.exec(space) : null;
    if (!owner) return { kind: 'none' };
    const chainId = owner[1]!;
    const address = owner[2]!.toLowerCase();
    owners.set(`did:pkh:eip155:${chainId}:${address}`, { chainId, address });
  }
  if (owners.size === 1) return { kind: 'owner', ...[...owners.values()][0]! };
  return { kind: 'conflict', owners: [...owners.keys()] };
}
