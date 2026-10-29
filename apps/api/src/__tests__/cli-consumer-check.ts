// The check a CLI applies to what OpenKey's /authorize-sign returns, copied
// from the published packages (not imported: the API does not depend on them):
//   - @tinycloud/node-sdk 3.8.0-beta.0 `dist/index.js`, NodeUserAuthorization:
//     the signedMessage / selectedActionKeys / permissions validation
//     (the "granted capability" index at ~L20385, Rule B ~L20427, Rule A,
//     and the `permissions` block ~L20477-20530);
//   - @tinycloud/sdk-core 3.7.0 `dist/index.js`: parseCanonicalRecapResource
//     (L16010), extractRecapAttenuations (L16117), unauthorizedRecapCapabilities.
// Error texts are kept as published. `throw` where the published code throws.

type Caps = Record<string, Record<string, unknown[]>>;

export interface CliResult {
  signedMessage: string;
  selectedActionKeys: string[];
  permissions: Array<{ service: string; space: string; path: string; actions: readonly string[] }>;
}

export function parseCanonicalRecapResource(resource: string): { space: string; path: string } {
  if (!resource.startsWith('tinycloud:')) return { space: resource, path: '' };
  const firstSlash = resource.indexOf('/');
  if (firstSlash < 0) return { space: resource, path: '' };
  const space = resource.slice(0, firstSlash);
  const rest = resource.slice(firstSlash + 1);
  const secondSlash = rest.indexOf('/');
  if (secondSlash < 0) return { space, path: '' };
  return { space, path: rest.slice(secondSlash + 1) };
}

export function extractRecapAttenuations(siwe: string): Caps {
  const merged: Caps = {};
  for (const line of siwe.split(/\r?\n/)) {
    const match = line.match(/urn:recap:([A-Za-z0-9_-]+=*)/);
    if (!match) continue;
    const normalized = match[1]!.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const parsed = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
    const att = parsed.att;
    if (att === undefined) continue;
    for (const [resource, actionMap] of Object.entries(att as Record<string, Record<string, unknown[]>>)) {
      const existing = merged[resource] ?? {};
      for (const [action, caveats] of Object.entries(actionMap)) {
        existing[action] = (existing[action] ?? []).concat(caveats);
      }
      merged[resource] = existing;
    }
  }
  return merged;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const entries = Object.entries(value as object).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`;
}

/** Throws the CLI's error for the first thing it would reject; returns when it would accept. */
export function cliConsumerCheck(preparedSiwe: string, result: CliResult): void {
  const originalCaps = extractRecapAttenuations(preparedSiwe);
  const signedCaps = extractRecapAttenuations(result.signedMessage);

  // unauthorizedRecapCapabilities(signedCaps, originalCaps)
  for (const [resource, actions] of Object.entries(signedCaps)) {
    for (const [action, caveats] of Object.entries(actions)) {
      const parentCaveats = originalCaps[resource]?.[action];
      if (parentCaveats === undefined || stableStringify(parentCaveats) !== stableStringify(caveats)) {
        throw new Error(`OpenKey signedMessage broadened authorization beyond the original request: ${resource}::${action}`);
      }
    }
  }

  const grantedPairs = new Set<string>();
  const grantedFourPartIndex = new Map<string, string>();
  for (const [resource, actions] of Object.entries(signedCaps)) {
    const { space, path } = parseCanonicalRecapResource(resource);
    for (const action of Object.keys(actions)) {
      grantedPairs.add(`${resource}\0${action}`);
      const slashIdx = action.indexOf('/');
      const service = slashIdx > 0 ? action.slice(0, slashIdx) : '';
      if (service) grantedFourPartIndex.set(`${service}\0${space}\0${path}\0${action}`, `${resource}\0${action}`);
    }
  }
  const isStructurallyRequired = (action: string) => action === 'tinycloud.capabilities/read' || action === 'capabilities/read';
  const nonRequiredGrantedPairs = new Set<string>();
  for (const pair of grantedPairs) {
    const idx = pair.indexOf('\0');
    const action = idx >= 0 ? pair.slice(idx + 1) : pair;
    if (!isStructurallyRequired(action)) nonRequiredGrantedPairs.add(pair);
  }
  const allSignedGrantedPairs = new Set(grantedPairs);

  const seenRawKeys = new Set<string>();
  for (const rawKey of result.selectedActionKeys) {
    if (seenRawKeys.has(rawKey)) throw new Error(`OpenKey selectedActionKeys contains duplicate entry ${rawKey}`);
    seenRawKeys.add(rawKey);
  }
  const selectedResourceActionPairs = new Set<string>();
  for (const rawKey of result.selectedActionKeys) {
    if (rawKey.split('\0').length !== 4) {
      throw new Error(`OpenKey selectedActionKeys entry is malformed (expected canonical 4-part service\\0space\\0path\\0ability): ${rawKey}`);
    }
    const canonical = grantedFourPartIndex.get(rawKey);
    if (!canonical) throw new Error(`OpenKey selectedActionKeys entry ${rawKey} is not covered by any granted capability`);
    selectedResourceActionPairs.add(canonical);
  }
  if (nonRequiredGrantedPairs.size > 0) {
    const missingPairs = [...nonRequiredGrantedPairs].filter((pair) => !selectedResourceActionPairs.has(pair));
    if (missingPairs.length > 0) {
      throw new Error(`OpenKey selectedActionKeys is missing entries for signedMessage capabilities: ${missingPairs.map((p) => p.replace('\0', '::')).join(', ')}`);
    }
  }

  if (allSignedGrantedPairs.size > 0 && result.permissions.length === 0) {
    throw new Error('OpenKey permissions is empty but signedMessage carries capabilities — refusing to accept a session without an authoritative grant list');
  }
  const permissionCanonicalKeys = new Set<string>();
  const permissionPairsCovered = new Set<string>();
  for (const perm of result.permissions) {
    const { service, space, path, actions } = perm;
    if (typeof service !== 'string' || typeof space !== 'string' || typeof path !== 'string') {
      throw new Error(`OpenKey permissions entry has non-string service/space/path (service=${service}, space=${space}, path=${path})`);
    }
    if (!Array.isArray(actions) || actions.length === 0) {
      throw new Error(`OpenKey permissions entry (${service} ${space} ${path}) has empty actions — a capability-bearing entry must list at least one action`);
    }
    const canonicalKey = `${service}\0${space}\0${path}`;
    if (permissionCanonicalKeys.has(canonicalKey)) throw new Error(`OpenKey permissions has duplicate entry for (${service} ${space} ${path})`);
    permissionCanonicalKeys.add(canonicalKey);
    let expectedResource: string;
    if (space.startsWith('tinycloud:')) {
      const shortService = service.startsWith('tinycloud.') ? service.slice('tinycloud.'.length) : service;
      expectedResource = path ? `${space}/${shortService}/${path}` : `${space}/${shortService}`;
    } else {
      if (path) {
        throw new Error(`OpenKey permissions entry (${service} ${space} ${path}) carries a path on a non-tinycloud: resource URI, which is not a recognized encoding`);
      }
      expectedResource = space;
    }
    if (signedCaps[expectedResource] === undefined) {
      throw new Error(`OpenKey permissions entry (${service} ${space} ${path}) claims grants not confirmed in signedMessage capabilities`);
    }
    const grantedActionsForResource = new Set(Object.keys(signedCaps[expectedResource]!));
    for (const action of actions) {
      if (typeof action !== 'string' || !action) throw new Error(`OpenKey permissions entry (${service} ${space} ${path}) has non-string action ${String(action)}`);
      if (!grantedActionsForResource.has(action)) {
        throw new Error(`OpenKey permissions entry (${service} ${space} ${path}) claims action ${action} not present in signedMessage capabilities`);
      }
      permissionPairsCovered.add(`${expectedResource}\0${action}`);
    }
  }
  if (allSignedGrantedPairs.size > 0) {
    const missingFromPerms = [...allSignedGrantedPairs].filter((pair) => !permissionPairsCovered.has(pair));
    if (missingFromPerms.length > 0) {
      throw new Error(`OpenKey permissions is missing entries for signedMessage capabilities: ${missingFromPerms.map((p) => p.replace('\0', '::')).join(', ')}`);
    }
    const extrasInPerms = [...permissionPairsCovered].filter((pair) => !allSignedGrantedPairs.has(pair));
    if (extrasInPerms.length > 0) {
      throw new Error(`OpenKey permissions contains entries not present in the signed authority: ${extrasInPerms.map((p) => p.replace('\0', '::')).join(', ')}`);
    }
  }
}
