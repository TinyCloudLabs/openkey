/** A `/delegate` request permission as the CLI encodes it. */
export interface DelegateRequestPermission {
  service: string;
  space?: string;
  path: string;
}

const SPACE_OWNER = /^tinycloud:pkh:eip155:\d+:(0x[a-fA-F0-9]{40}):/;
const RAW_ENCRYPTION_OWNER = /^urn:tinycloud:encryption:did:pkh:eip155:\d+:(0x[a-fA-F0-9]{40}):/;

/**
 * The (lowercase) owner address every permission of the request resolves to,
 * or null. A space permission resolves through its
 * `tinycloud:pkh:eip155:<chain>:<addr>:<name>` space URI, a raw encryption
 * network through its `urn:tinycloud:encryption:did:pkh:eip155:<chain>:<addr>:<name>`
 * owner. Any permission without a pkh owner, or owners that disagree, yield
 * null so the UI does not pin a wallet for an unscoped or mixed request.
 */
export function expectedSignerAddress(permissions: readonly DelegateRequestPermission[]): string | null {
  if (permissions.length === 0) return null;
  const addresses = new Set<string>();
  for (const permission of permissions) {
    const isRawEncryption =
      (permission.service === 'tinycloud.encryption' || permission.service === 'encryption') &&
      permission.path.startsWith('urn:tinycloud:encryption:');
    const owner = isRawEncryption
      ? RAW_ENCRYPTION_OWNER.exec(permission.path)
      : typeof permission.space === 'string' ? SPACE_OWNER.exec(permission.space) : null;
    if (!owner) return null;
    addresses.add(owner[1]!.toLowerCase());
  }
  return addresses.size === 1 ? [...addresses][0]! : null;
}
