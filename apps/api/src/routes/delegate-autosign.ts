import {
  BOOTSTRAP_ALLOWLIST,
  SPACE,
  bootstrapSpaceId,
  type BootstrapAllowlistEntry,
  type BootstrapAllowlistKind,
  type BootstrapSpaceName,
} from '@tinycloud/bootstrap';

export interface RecapEntry {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

export type AutoSignPolicyCode =
  | 'auto_sign_disabled'
  | 'outside_bootstrap_allowlist'
  | 'owner_only_path';

export type AutoSignPolicyDecision =
  | { allowed: true }
  | { allowed: false; code: AutoSignPolicyCode; reason: string };

interface ScopeEvaluationInput {
  entries: RecapEntry[];
  address: string;
  chainId: number;
  spaceId: string;
}

interface SigningScopeEvaluationInput {
  entries: RecapEntry[];
  address: string;
  chainId: number;
}

const bootstrapSpaces = new Set<BootstrapSpaceName>(
  BOOTSTRAP_ALLOWLIST.map((entry) => entry.space),
);

function spaceNameFromId(spaceId: string): string {
  const separator = spaceId.lastIndexOf(':');
  return separator >= 0 ? spaceId.slice(separator + 1) : spaceId;
}

function isBootstrapSpaceName(space: string): space is BootstrapSpaceName {
  return bootstrapSpaces.has(space as BootstrapSpaceName);
}

function fullServiceName(service: string): string {
  return service.startsWith('tinycloud.') ? service : `tinycloud.${service}`;
}

function actionSubset(requested: readonly string[], allowed: readonly string[]): boolean {
  const allowedActions = new Set(allowed);
  return requested.every((action) => allowedActions.has(action));
}

function allowlistEntry(kind: BootstrapAllowlistKind, space: BootstrapSpaceName): BootstrapAllowlistEntry | undefined {
  return BOOTSTRAP_ALLOWLIST.find(
    (entry) => entry.kind === kind && entry.space === space,
  );
}

function ownerDid(address: string, chainId: number): string {
  return `did:pkh:eip155:${chainId}:${address}`;
}

function expandRawResource(resource: string, address: string, chainId: number): string {
  return resource.replace('{ownerDid}', ownerDid(address, chainId));
}

function scopeSpaceId(entries: RecapEntry[]): string | undefined {
  return entries.find((entry) => entry.space.startsWith('tinycloud:'))?.space;
}

function isHostSigningScope(entries: RecapEntry[]): boolean {
  return entries.some((entry) => (
    fullServiceName(entry.service) === 'tinycloud.space' ||
    entry.actions.includes(SPACE.HOST)
  ));
}

function denied(reason: string): AutoSignPolicyDecision {
  return { allowed: false, code: 'outside_bootstrap_allowlist', reason };
}

// Paths whose writes must come from the owner's own passkey session, never
// from Auto-Sign (TC-884). The Courier approval loop rests on this: a request
// or order only counts when the owner approved it with a passkey tap. A ReCap
// cannot carve an exception out of a broader grant, so any Auto-Sign request
// that could write here, including a whole-space grant, is refused.
// Compared lowercase, as raw string prefixes, so a name that merely starts
// the same way is refused too; over-refusing only costs a passkey tap.
const OWNER_ONLY_SPACE = 'agents';
const OWNER_ONLY_PATHS: readonly string[] = [
  'xyz.tinycloud.courier/me/approvals',
  'xyz.tinycloud.courier/me/orders',
];
const READ_ONLY_KV_VERBS: Record<string, true> = { get: true, list: true, metadata: true };

function pathReachesOwnerOnly(path: string): boolean {
  const normalized = path.toLowerCase().replace(/^\/+/, '');
  // Forms the node might normalize differently from a string comparison are
  // refused rather than interpreted.
  if (normalized.includes('%') || normalized.includes('\\')) {
    return true;
  }
  const segments = normalized.split('/');
  const ambiguous = segments.some((segment, index) => (
    segment === '.' ||
    segment === '..' ||
    (segment === '' && index < segments.length - 1)
  ));
  if (ambiguous) {
    return true;
  }
  return OWNER_ONLY_PATHS.some((owned) => (
    owned.startsWith(normalized) || normalized.startsWith(owned)
  ));
}

function evaluateOwnerOnlyPaths(entries: RecapEntry[]): AutoSignPolicyDecision {
  for (const entry of entries) {
    if (
      fullServiceName(entry.service) !== 'tinycloud.kv' ||
      spaceNameFromId(entry.space) !== OWNER_ONLY_SPACE
    ) {
      continue;
    }
    // Anything that is not a plain read counts as a write, so an unknown
    // verb fails closed.
    const writes = entry.actions.some((action) => (
      READ_ONLY_KV_VERBS[action.slice(action.lastIndexOf('/') + 1).toLowerCase()] !== true
    ));
    if (writes && pathReachesOwnerOnly(entry.path)) {
      return {
        allowed: false,
        code: 'owner_only_path',
        reason: 'Writes to Courier approvals and orders need a passkey approval, not Auto-Sign',
      };
    }
  }
  return { allowed: true };
}

function bootstrapSpaceForRequest({ address, chainId, spaceId }: ScopeEvaluationInput): {
  space: BootstrapSpaceName;
  expectedSpaceId: string;
} | AutoSignPolicyDecision {
  const space = spaceNameFromId(spaceId);
  if (!isBootstrapSpaceName(space)) {
    return denied('Requested space is not an enshrined bootstrap space');
  }

  const expectedSpaceId = bootstrapSpaceId(address, chainId, space);
  if (spaceId !== expectedSpaceId) {
    return denied('Requested space ID does not match the signer address and chain');
  }

  return { space, expectedSpaceId };
}

export function evaluateBootstrapSessionScope(input: ScopeEvaluationInput): AutoSignPolicyDecision {
  const ownerOnly = evaluateOwnerOnlyPaths(input.entries);
  if (!ownerOnly.allowed) {
    return ownerOnly;
  }

  const bootstrapSpace = bootstrapSpaceForRequest(input);
  if ('allowed' in bootstrapSpace) {
    return bootstrapSpace;
  }

  const allowed = allowlistEntry('session', bootstrapSpace.space);
  if (!allowed) {
    return denied('No bootstrap session allowlist entry exists for this space');
  }

  if (input.entries.length === 0) {
    return denied('Signed SIWE message does not contain bootstrap capabilities');
  }

  for (const entry of input.entries) {
    const service = fullServiceName(entry.service);
    if (service === 'tinycloud.encryption') {
      if (entry.space !== 'encryption') {
        return denied('Requested raw capability is outside the bootstrap allowlist');
      }

      const rawAbility = allowed.rawAbilities?.find((ability) => (
        ability.service === service &&
        expandRawResource(ability.resource, input.address, input.chainId) === entry.path &&
        actionSubset(entry.actions, ability.actions)
      ));

      if (!rawAbility) {
        return denied('Requested raw capability is outside the bootstrap allowlist');
      }
      continue;
    }

    if (entry.space !== bootstrapSpace.expectedSpaceId) {
      return denied('Requested capability targets a space outside the bootstrap request');
    }

    const resource = allowed.resources?.find((candidate) => (
      candidate.service === service &&
      candidate.space === bootstrapSpace.space &&
      candidate.path === entry.path &&
      actionSubset(entry.actions, candidate.actions)
    ));

    if (!resource) {
      return denied('Requested capability is outside the bootstrap allowlist');
    }
  }

  return { allowed: true };
}

export function evaluateBootstrapSigningScope(
  input: SigningScopeEvaluationInput,
  allowlist: readonly BootstrapAllowlistEntry[] = BOOTSTRAP_ALLOWLIST,
): AutoSignPolicyDecision {
  const ownerOnly = evaluateOwnerOnlyPaths(input.entries);
  if (!ownerOnly.allowed) {
    return ownerOnly;
  }

  if (isHostSigningScope(input.entries)) {
    const spaceId = scopeSpaceId(input.entries);
    if (!spaceId) {
      return denied('Signed SIWE message does not target a bootstrap space');
    }
    return evaluateBootstrapHostScope({ ...input, spaceId });
  }

  return evaluateBootstrapSessionCandidates(input, allowlist);
}

function evaluateBootstrapSessionCandidates(
  input: SigningScopeEvaluationInput,
  allowlist: readonly BootstrapAllowlistEntry[],
): AutoSignPolicyDecision {
  if (input.entries.length === 0) {
    return denied('Signed SIWE message does not contain bootstrap capabilities');
  }

  const candidates = allowlist.filter(
    (entry) => entry.kind === 'session',
  );
  const validCandidates = candidates.filter((candidate) => {
    let hasPrimaryAnchor = false;

    for (const entry of input.entries) {
      const service = fullServiceName(entry.service);
      if (service === 'tinycloud.encryption') {
        if (entry.space !== 'encryption') {
          return false;
        }

        const rawAbility = candidate.rawAbilities?.find((ability) => (
          ability.service === service &&
          expandRawResource(ability.resource, input.address, input.chainId) === entry.path &&
          actionSubset(entry.actions, ability.actions)
        ));
        if (!rawAbility) {
          return false;
        }
        continue;
      }

      const resource = candidate.resources?.find((allowedResource) => (
        fullServiceName(allowedResource.service) === service &&
        allowedResource.path === entry.path &&
        actionSubset(entry.actions, allowedResource.actions) &&
        isBootstrapSpaceName(allowedResource.space) &&
        entry.space === bootstrapSpaceId(input.address, input.chainId, allowedResource.space)
      ));
      if (!resource) {
        return false;
      }

      if (
        entry.space === bootstrapSpaceId(input.address, input.chainId, candidate.space)
      ) {
        hasPrimaryAnchor = true;
      }
    }

    return hasPrimaryAnchor;
  });

  if (validCandidates.length === 1) {
    return { allowed: true };
  }
  if (validCandidates.length > 1) {
    return denied('Ambiguous bootstrap candidates');
  }

  const hasAnchorlessMatch = candidates.some((candidate) => {
    let hasPrimaryAnchor = false;
    for (const entry of input.entries) {
      const service = fullServiceName(entry.service);
      if (service === 'tinycloud.encryption') {
        const rawAbility = candidate.rawAbilities?.find((ability) => (
          ability.service === service &&
          entry.space === 'encryption' &&
          expandRawResource(ability.resource, input.address, input.chainId) === entry.path &&
          actionSubset(entry.actions, ability.actions)
        ));
        if (!rawAbility) return false;
        continue;
      }
      const resource = candidate.resources?.find((allowedResource) => (
        fullServiceName(allowedResource.service) === service &&
        allowedResource.path === entry.path &&
        actionSubset(entry.actions, allowedResource.actions) &&
        isBootstrapSpaceName(allowedResource.space) &&
        entry.space === bootstrapSpaceId(input.address, input.chainId, allowedResource.space)
      ));
      if (!resource) return false;
      if (entry.space === bootstrapSpaceId(input.address, input.chainId, candidate.space)) {
        hasPrimaryAnchor = true;
      }
    }
    return !hasPrimaryAnchor;
  });

  return denied(
    hasAnchorlessMatch
      ? 'Missing primary-space anchor for bootstrap candidate'
      : 'No bootstrap candidate explains the complete recap',
  );
}

export function evaluateBootstrapHostScope(input: ScopeEvaluationInput): AutoSignPolicyDecision {
  const bootstrapSpace = bootstrapSpaceForRequest(input);
  if ('allowed' in bootstrapSpace) {
    return bootstrapSpace;
  }

  const allowed = allowlistEntry('space/host', bootstrapSpace.space);
  if (!allowed) {
    return denied('No bootstrap host allowlist entry exists for this space');
  }

  if (input.entries.length === 0) {
    return denied('Signed SIWE message does not contain bootstrap host capability');
  }

  for (const entry of input.entries) {
    if (entry.space !== bootstrapSpace.expectedSpaceId) {
      return denied('Requested host delegation targets a space outside the bootstrap request');
    }

    if (
      fullServiceName(entry.service) !== allowed.service ||
      entry.path !== '' ||
      !actionSubset(entry.actions, allowed.actions)
    ) {
      return denied('Requested host delegation is outside the bootstrap allowlist');
    }
  }

  return { allowed: true };
}

export function evaluateAutoSignPolicy(
  autoSignEnabled: boolean,
  scopeDecision: AutoSignPolicyDecision,
): AutoSignPolicyDecision {
  if (!autoSignEnabled) {
    return {
      allowed: false,
      code: 'auto_sign_disabled',
      reason: 'Auto-Sign is disabled for this account',
    };
  }

  return scopeDecision;
}
