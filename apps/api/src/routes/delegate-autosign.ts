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
  | 'outside_bootstrap_allowlist';

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

export function evaluateBootstrapSigningScope(input: SigningScopeEvaluationInput): AutoSignPolicyDecision {
  const spaceId = scopeSpaceId(input.entries);
  if (!spaceId) {
    return denied('Signed SIWE message does not target a bootstrap space');
  }

  if (isHostSigningScope(input.entries)) {
    return evaluateBootstrapHostScope({ ...input, spaceId });
  }

  return evaluateBootstrapSessionScope({ ...input, spaceId });
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
