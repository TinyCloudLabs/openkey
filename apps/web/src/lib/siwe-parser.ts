/**
 * Minimal SIWE (Sign-In with Ethereum) message parser.
 * Extracts structured fields and ReCap capabilities from a SIWE message string.
 */

export interface SIWEMessage {
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version: string;
  chainId: number;
  nonce: string;
  issuedAt?: string;
  expirationTime?: string;
  resources: string[];
}

export interface RecapAbility {
  namespace: string;
  action: string;
}

export interface RecapCapability {
  /** e.g. "tinycloud.kv" */
  resource: string;
  /** e.g. ["put", "get", "del", "list", "metadata"] */
  abilities: RecapAbility[];
}

export interface ParsedSIWE {
  message: SIWEMessage;
  recap: RecapCapability[] | null;
  raw: string;
}

const SIWE_PATTERN = /^(.+) wants you to sign in with your Ethereum account:\n(0x[a-fA-F0-9]{40})\n/;

/**
 * Try to parse a string as a SIWE message.
 * Returns null if the string doesn't match the SIWE format.
 */
export function parseSIWE(raw: string): ParsedSIWE | null {
  const match = raw.match(SIWE_PATTERN);
  if (!match) return null;

  const domain = match[1];
  const address = match[2];

  // Extract fields from the message body
  const statement = extractBetween(raw, `${address}\n`, '\n\nURI:');
  const uri = extractField(raw, 'URI:');
  const version = extractField(raw, 'Version:');
  const chainId = parseInt(extractField(raw, 'Chain ID:') || '1', 10);
  const nonce = extractField(raw, 'Nonce:');
  const issuedAt = extractField(raw, 'Issued At:');
  const expirationTime = extractField(raw, 'Expiration Time:');

  // Extract resources
  const resources: string[] = [];
  const resourcesMatch = raw.match(/Resources:\n([\s\S]*)$/);
  if (resourcesMatch) {
    const lines = resourcesMatch[1].split('\n');
    for (const line of lines) {
      const trimmed = line.replace(/^- /, '').trim();
      if (trimmed) resources.push(trimmed);
    }
  }

  const message: SIWEMessage = {
    domain,
    address,
    statement: statement?.trim() || undefined,
    uri: uri || '',
    version: version || '1',
    chainId,
    nonce: nonce || '',
    issuedAt: issuedAt || undefined,
    expirationTime: expirationTime || undefined,
    resources,
  };

  // Parse ReCap from resources
  const recap = parseRecap(resources);

  return { message, recap, raw };
}

/**
 * Parse ReCap capabilities from SIWE resource URNs.
 * ReCap URNs look like: urn:recap:eyJ...  (base64url-encoded JSON)
 */
function parseRecap(resources: string[]): RecapCapability[] | null {
  for (const resource of resources) {
    if (!resource.startsWith('urn:recap:')) continue;

    const b64 = resource.slice('urn:recap:'.length);
    try {
      // base64url → base64 → decode
      const json = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
      const recap = JSON.parse(json);

      // ReCap format: { att: { "resource": { "action": [{}] } } }
      if (!recap.att) return null;

      const capabilities: RecapCapability[] = [];

      for (const [resource, actions] of Object.entries(recap.att)) {
        const abilities: RecapAbility[] = [];

        for (const actionKey of Object.keys(actions as Record<string, unknown>)) {
          // Action keys look like "tinycloud.kv/put" or "namespace/action"
          const slashIdx = actionKey.indexOf('/');
          if (slashIdx >= 0) {
            abilities.push({
              namespace: actionKey.slice(0, slashIdx),
              action: actionKey.slice(slashIdx + 1),
            });
          } else {
            abilities.push({ namespace: '', action: actionKey });
          }
        }

        capabilities.push({ resource, abilities });
      }

      return capabilities;
    } catch {
      // Invalid base64 or JSON
      continue;
    }
  }

  return null;
}

function extractField(text: string, field: string): string | undefined {
  const regex = new RegExp(`${field}\\s*(.+)`);
  const match = text.match(regex);
  return match?.[1]?.trim();
}

function extractBetween(text: string, start: string, end: string): string | undefined {
  const startIdx = text.indexOf(start);
  if (startIdx < 0) return undefined;
  const afterStart = startIdx + start.length;
  const endIdx = text.indexOf(end, afterStart);
  if (endIdx < 0) return undefined;
  return text.slice(afterStart, endIdx);
}

/**
 * Group recap abilities by namespace for display.
 * e.g. [{ namespace: "tinycloud.kv", action: "put" }, { namespace: "tinycloud.kv", action: "get" }]
 * → [{ namespace: "tinycloud.kv", actions: ["put", "get"] }]
 */
export interface GroupedCapability {
  namespace: string;
  label: string;
  actions: string[];
  /** The resource URI this capability applies to */
  resource: string;
  /** A short display-friendly version of the resource path */
  resourcePath: string;
}

const NAMESPACE_LABELS: Record<string, string> = {
  'tinycloud.kv': 'Key-Value Storage',
  'tinycloud.sql': 'SQL Database',
  'tinycloud.space': 'Space Management',
  'tinycloud.capabilities': 'Capabilities',
};

/**
 * Extract a short display path from a resource URI.
 * Resource keys typically look like:
 *   "urn:recap:resource:pkh:eip155:1:0xABCD...:kv/my-store"
 * Strip the PKH address prefix and return just the service/path portion.
 */
function extractResourcePath(resource: string): string {
  // Strip PKH address prefix: everything after 0x<40 hex chars>:
  const pkhMatch = resource.match(/0x[a-fA-F0-9]{40}:(.+)$/);
  if (pkhMatch) {
    return pkhMatch[1];
  }
  // For URN-style without PKH, take the last meaningful segment
  if (resource.startsWith('urn:')) {
    const parts = resource.split(':');
    return parts[parts.length - 1] || resource;
  }
  // For URL-style resources, show the path
  try {
    const url = new URL(resource);
    return url.pathname === '/' ? url.hostname : url.pathname;
  } catch {
    return resource;
  }
}

export function groupCapabilities(recap: RecapCapability[]): GroupedCapability[] {
  // Group by resource + namespace so that two different resources with the same
  // namespace are shown separately (e.g. two KV stores with different permissions).
  const byKey = new Map<string, { namespace: string; resource: string; actions: string[] }>();

  for (const cap of recap) {
    for (const ability of cap.abilities) {
      const ns = ability.namespace;
      const key = `${cap.resource}\0${ns}`;
      if (!byKey.has(key)) {
        byKey.set(key, { namespace: ns, resource: cap.resource, actions: [] });
      }
      byKey.get(key)!.actions.push(ability.action);
    }
  }

  const result: GroupedCapability[] = [];
  for (const { namespace, resource, actions } of byKey.values()) {
    result.push({
      namespace,
      label: NAMESPACE_LABELS[namespace] || namespace,
      actions,
      resource,
      resourcePath: extractResourcePath(resource),
    });
  }

  return result;
}

/**
 * Compute a human-readable relative time string until the given ISO timestamp.
 * Returns "Expired" if the time is in the past.
 */
export function timeUntilExpiry(iso: string): { text: string; expired: boolean } {
  const now = Date.now();
  const target = new Date(iso).getTime();
  const diff = target - now;

  if (diff <= 0) {
    return { text: 'Expired', expired: true };
  }

  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) {
    return { text: `in ${days} day${days === 1 ? '' : 's'}`, expired: false };
  }
  if (hours > 0) {
    return { text: `in ${hours} hour${hours === 1 ? '' : 's'}`, expired: false };
  }
  if (minutes > 0) {
    return { text: `in ${minutes} minute${minutes === 1 ? '' : 's'}`, expired: false };
  }
  return { text: `in ${seconds} second${seconds === 1 ? '' : 's'}`, expired: false };
}
