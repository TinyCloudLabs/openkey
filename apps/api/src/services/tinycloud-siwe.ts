// What a TinyCloud sign-in asks for, read from its SIWE/ReCap: whether it makes OpenKey set up the
// signer's account before signing (TC-1608), and which of the signer's own spaces it names.
//
// Pure (no database, no node), so the signing route can read it without loading the bootstrap, and so the
// delegate route and the sign route share one "is this the signer's own canonical space" check.

import {
  BOOTSTRAP_SPACE_NAMES,
  CAPABILITIES,
  ENCRYPTION,
  KV,
  SQL,
  type BootstrapSpaceName,
} from '@tinycloud/bootstrap';
import { siweExpirationTime } from '@openkey/capability-review';
import { ensureEip55, parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { decodeHexUtf8 } from './siwe-origin';

const NETWORK_CREATE_ACTION = ENCRYPTION.NETWORK_CREATE;

export interface RecapEntry {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

export interface ParsedTinyCloudSiwe {
  address: string;
  chainId: number;
  expirationTime?: Date;
  entries: RecapEntry[];
}

export function parseTinyCloudSiwe(message: string): ParsedTinyCloudSiwe | null {
  const header = message.match(/^.+ wants you to sign in with your Ethereum account:\n(0x[a-fA-F0-9]{40})\n/);
  if (!header?.[1]) {
    return null;
  }

  const chainIdMatch = message.match(/^Chain ID:\s*(\d+)\s*$/m);
  if (!chainIdMatch?.[1]) {
    return null;
  }

  let entries: RecapEntry[];
  try {
    entries = parseRecapFromSiwe(message) as RecapEntry[];
  } catch {
    return null;
  }

  if (!Array.isArray(entries) || entries.length === 0) {
    return null;
  }

  const expirationTime = siweExpirationTime(message);

  return {
    address: ensureEip55(header[1]),
    chainId: Number(chainIdMatch[1]),
    expirationTime: expirationTime !== null ? new Date(expirationTime) : undefined,
    entries,
  };
}

/** The abilities in the `space` namespace: `host` creates a space on the node. */
const SPACE_ABILITY_PREFIX = 'tinycloud.space/';
export const SPACE_HOST_ABILITY = 'tinycloud.space/host';
/** Space abilities that read and create nothing. Matched as exact strings, with no prefix match, case folding or trim. */
const SPACE_READ_ABILITIES: readonly string[] = ['tinycloud.space/list', 'tinycloud.space/info'];

export interface SpaceHostTarget {
  address: string;
  chainId: number;
  /** The space's name: the part of its id after the owner (`default`, `public`, an app's own name). */
  name: string;
}

/** What signing a message lets a site do about spaces on the node. */
export type SpaceHostRequest =
  /** No space ability in it. */
  | { kind: 'none' }
  /** A space ability whose targets cannot be read, or any space ability other than `host`, `list` and `info` (a wildcard, say). */
  | { kind: 'unreadable' }
  /** `host` for exactly these spaces: every one is derived from the ReCap's own resources. */
  | { kind: 'hosts'; targets: SpaceHostTarget[] };

const SPACE_ID = /^tinycloud:pkh:eip155:(\d+):(0x[0-9a-fA-F]{40}):([^\s:/][^\s]*)$/;

/** Any ReCap resource, in any case: the text is parsed whenever one is present, never judged from its raw bytes. */
const RECAP_RESOURCE = /urn:recap:/i;

/**
 * Reads what a message would let a site do with spaces: as written and, for `0x…` hex, as the UTF-8 bytes a signature
 * would cover. A message with any ReCap resource is parsed by the same wasm parser the node reads it with, so JSON
 * escapes, unicode escapes, duplicate keys and the rest are decoded exactly as the node decodes them; the raw bytes
 * are never searched. The targets come from the parsed entries (owner address and name out of the space id), never
 * from the text around them. A ReCap that cannot be parsed to the end is `unreadable`, as is a space-agnostic,
 * wildcard or other space ability and a target that is not a space id: the answer is then to refuse. The exact
 * abilities `tinycloud.space/list` and `tinycloud.space/info` read and create nothing: an entry with only those
 * names no target.
 */
export function spaceHostRequest(message: string): SpaceHostRequest {
  const decoded = decodeHexUtf8(message);
  const targets: SpaceHostTarget[] = [];
  for (const text of decoded === null ? [message] : [message, decoded]) {
    if (!RECAP_RESOURCE.test(text)) continue;
    let entries: RecapEntry[];
    try {
      entries = parseRecapFromSiwe(text) as RecapEntry[];
    } catch {
      return { kind: 'unreadable' };
    }
    if (!Array.isArray(entries)) return { kind: 'unreadable' };
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object' || !Array.isArray(entry.actions ?? [])) return { kind: 'unreadable' };
      const service = typeof entry.service === 'string' ? entry.service.toLowerCase() : '';
      const actions = entry.actions ?? [];
      if (actions.some((action) => typeof action !== 'string')) return { kind: 'unreadable' };
      const spaceActions = service === 'space' || service === 'tinycloud.space'
        ? actions
        : actions.filter((action) => action.toLowerCase().startsWith(SPACE_ABILITY_PREFIX) || action === '*');
      if (spaceActions.length === 0) continue;
      if (spaceActions.some((action) => action !== SPACE_HOST_ABILITY && !SPACE_READ_ABILITIES.includes(action))) return { kind: 'unreadable' };
      if (!spaceActions.includes(SPACE_HOST_ABILITY)) continue;
      const id = SPACE_ID.exec(entry.space ?? '');
      if (!id) return { kind: 'unreadable' };
      let address: string;
      try {
        address = ensureEip55(id[2]!);
      } catch {
        return { kind: 'unreadable' };
      }
      targets.push({ chainId: Number(id[1]), address, name: id[3]! });
    }
  }
  return targets.length === 0 ? { kind: 'none' } : { kind: 'hosts', targets };
}

/**
 * The canonical bootstrap space name when `spaceId` is exactly one of THIS address's own bootstrap
 * spaces on this chain (`tinycloud:pkh:eip155:<chain>:<EIP-55 address>:<name>`), otherwise null. Another
 * account's space, another chain, an address that is not spelled EIP-55 and a name that is not a bootstrap space all return
 * null. (A lower-case address in a real message never gets here as such: the SIWE parser normalises it to
 * EIP-55 first, and it is still the signer's own space.)
 */
export function ownBootstrapSpaceName(spaceId: string, address: string, chainId: number): BootstrapSpaceName | null {
  const name = spaceId.slice(spaceId.lastIndexOf(':') + 1);
  if (!isBootstrapSpaceName(name)) return null;
  // Built as text, not through the wasm `makeSpaceId`, which throws on a chain id it rejects (0): a message
  // like that must not stop the signature, it just names no own space.
  return spaceId === `tinycloud:pkh:eip155:${chainId}:${ensureEip55(address)}:${name}` ? name : null;
}

function isBootstrapSpaceName(name: string): name is BootstrapSpaceName {
  return (BOOTSTRAP_SPACE_NAMES as readonly string[]).includes(name);
}

/**
 * Whether this sign-in by `keyAddress` makes OpenKey set up the account before signing: it asks for the
 * account space's own entries, or it names one of the signer's OWN canonical bootstrap spaces (an app
 * that asks only for `applications` is the case that needs it: nothing else would host that space for a
 * new account, so the SDK would offer to create it).
 */
export function isTinyCloudSiweForSigner(
  parsed: ParsedTinyCloudSiwe,
  keyAddress: string,
): boolean {
  const address = ensureEip55(keyAddress);
  if (ensureEip55(parsed.address) !== address) {
    return false;
  }

  return parsed.entries.some((entry) => isAccountBootstrapEntry(entry, parsed.chainId, address))
    || parsed.entries.some((entry) => ownBootstrapSpaceName(entry.space, address, parsed.chainId) !== null);
}

/** The order the signer's own spaces are awaited in: applications first, then the bootstrap's own order. */
const AWAIT_ORDER: readonly BootstrapSpaceName[] = [
  'applications',
  ...BOOTSTRAP_SPACE_NAMES.filter((name) => name !== 'applications'),
];

/**
 * The one space of the signer's own that this sign-in names and that the approval waits for (it is hosted
 * before the signature is returned; the rest of the setup follows in the background), or null when there
 * is none. Null for a sign-in that already asks for the account space's own entries: that one runs the
 * whole setup, as before. Never a space of another account: only `ownBootstrapSpaceName` matches count.
 */
export function requestedOwnSpaceForSiwe(
  parsed: ParsedTinyCloudSiwe,
  keyAddress: string,
): BootstrapSpaceName | null {
  const address = ensureEip55(keyAddress);
  if (ensureEip55(parsed.address) !== address) {
    return null;
  }
  if (parsed.entries.some((entry) => isAccountBootstrapEntry(entry, parsed.chainId, address))) {
    return null;
  }
  const named = new Set<BootstrapSpaceName>();
  for (const entry of parsed.entries) {
    const name = ownBootstrapSpaceName(entry.space, address, parsed.chainId);
    if (name) named.add(name);
  }
  return AWAIT_ORDER.find((name) => named.has(name)) ?? null;
}

function isAccountBootstrapEntry(entry: RecapEntry, chainId: number, address: string): boolean {
  const accountSpace = `tinycloud:pkh:eip155:${chainId}:${address}:account`;
  const defaultEncryptionNetwork = `urn:tinycloud:encryption:did:pkh:eip155:${chainId}:${address}:default`;
  if (entry.path === defaultEncryptionNetwork) {
    return entry.actions.includes(NETWORK_CREATE_ACTION);
  }
  if (entry.space !== accountSpace) {
    return false;
  }

  return (
    entry.service === 'capabilities' &&
    (entry.path === '' || entry.path === 'capabilities') &&
    entry.actions.includes(CAPABILITIES.READ)
  ) || (
    entry.service === 'kv' &&
    (entry.path === 'applications/' || entry.path === 'spaces/') &&
    hasAnyAction(entry.actions, [KV.GET, KV.LIST, KV.PUT])
  ) || (
    entry.service === 'sql' &&
    entry.path === 'account' &&
    hasAnyAction(entry.actions, [SQL.READ, SQL.SCHEMA, SQL.WRITE])
  );
}

function hasAnyAction(actions: string[], expected: string[]): boolean {
  return expected.some((action) => actions.includes(action));
}
