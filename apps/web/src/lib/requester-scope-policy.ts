import { parseEncryptionResource } from '@openkey/capability-review';

/**
 * What a verified requester may ask for. A listed requester keeps its verified name only for a request inside its
 * policy; any other request from the same key is shown as not verified, with the reason from `checkRequesterScope`.
 *
 * A rule covers one service, and may pin the `spaces` a permission names (any space when absent).
 * - `path` rules match a resource path of exactly `segmentsAfterPrefix` clean segments under one of the prefixes. A
 *   path equal to a prefix, or with an empty, `.` or `..` segment, is outside.
 * - `encryption-network` rules match an encryption resource on one network: the network itself when `wholeNetwork`
 *   is set, and a key whose path is a key prefix followed by one name (`[a-z0-9][a-z0-9_-]*`). Prefixes and keys
 *   elsewhere on the network are outside.
 * The owner inside an encryption resource is not checked here: it is not known when the requester is named, and the
 * approver can only grant resources of their own.
 */
export type RequesterScopeRule =
  | { kind: 'path'; service: string; spaces?: readonly string[]; actions: readonly string[]; pathPrefixes: readonly string[]; segmentsAfterPrefix: number }
  | { kind: 'encryption-network'; service: string; spaces?: readonly string[]; actions: readonly string[]; network: string; wholeNetwork: boolean; keyPrefixes: readonly string[] };

export type RequesterScopePolicy = {
  /** The longest grant the requester may ask for. */
  maxLifetimeSeconds: number;
  /** Every requested permission must fit one rule. */
  rules: readonly RequesterScopeRule[];
};

export type RequesterScopeRefusal =
  | 'malformed'
  | 'no-permissions'
  | 'lifetime'
  | 'service'
  | 'action'
  | 'space'
  | 'path'
  | 'renewal'
  | 'context';

export type RequesterScopeVerdict = { ok: true } | { ok: false; reason: RequesterScopeRefusal };

/** The parts of a parsed approval request the policy reads. Unknown JSON is checked, not trusted. */
export type RequesterScopeRequest = {
  permissions: unknown;
  grantLifetimeSeconds: unknown;
  renewal?: unknown;
  context?: unknown;
};

const NETWORK = /^[a-z0-9][a-z0-9-]*$/;
const KEY_NAME = /^[a-z0-9][a-z0-9_-]*$/;

function isCleanPrefix(prefix: string): boolean {
  return prefix.endsWith('/') && prefix.length > 1 && !hasUnsafeSegment(prefix.slice(0, -1));
}

function hasUnsafeSegment(path: string): boolean {
  if (/[\\\u0000-\u001f\u007f]/.test(path)) return true;
  return path.split('/').some((segment) => segment === '' || segment === '.' || segment === '..');
}

/** Whether a policy is well formed: a bounded lifetime and at least one precise rule. */
export function isRequesterScopePolicy(policy: RequesterScopePolicy | null | undefined): boolean {
  if (!policy || typeof policy !== 'object') return false;
  if (!Number.isSafeInteger(policy.maxLifetimeSeconds) || policy.maxLifetimeSeconds <= 0) return false;
  if (!Array.isArray(policy.rules) || policy.rules.length === 0) return false;
  return policy.rules.every((rule) => {
    if (!rule || typeof rule !== 'object') return false;
    if (typeof rule.service !== 'string' || rule.service === '') return false;
    if (!Array.isArray(rule.actions) || rule.actions.length === 0 || rule.actions.some((action: unknown) => typeof action !== 'string' || action === '')) return false;
    if (rule.spaces !== undefined && (!Array.isArray(rule.spaces) || rule.spaces.length === 0 || rule.spaces.some((space: unknown) => typeof space !== 'string' || space === ''))) return false;
    if (rule.kind === 'path') {
      return Array.isArray(rule.pathPrefixes) && rule.pathPrefixes.length > 0 && rule.pathPrefixes.every(isCleanPrefix) &&
        Number.isSafeInteger(rule.segmentsAfterPrefix) && rule.segmentsAfterPrefix > 0;
    }
    if (rule.kind === 'encryption-network') {
      return typeof rule.network === 'string' && NETWORK.test(rule.network) && typeof rule.wholeNetwork === 'boolean' &&
        Array.isArray(rule.keyPrefixes) && rule.keyPrefixes.every(isCleanPrefix) && (rule.wholeNetwork || rule.keyPrefixes.length > 0);
    }
    return false;
  });
}

function pathFits(rule: RequesterScopeRule, path: string): boolean {
  if (rule.kind === 'path') {
    return rule.pathPrefixes.some((prefix) => {
      if (!path.startsWith(prefix) || hasUnsafeSegment(path)) return false;
      return path.slice(prefix.length).split('/').length === rule.segmentsAfterPrefix;
    });
  }
  const resource = parseEncryptionResource(path);
  if (resource?.network !== rule.network) return false;
  if (resource.kind === 'network') return rule.wholeNetwork;
  if (resource.kind !== 'key') return false;
  return rule.keyPrefixes.some((prefix) => resource.keyPath.startsWith(prefix) && KEY_NAME.test(resource.keyPath.slice(prefix.length)));
}

/** Whether a request stays inside a requester's policy, and the first reason when it does not. */
export function checkRequesterScope(policy: RequesterScopePolicy, request: RequesterScopeRequest): RequesterScopeVerdict {
  const refuse = (reason: RequesterScopeRefusal): RequesterScopeVerdict => ({ ok: false, reason });
  if (!isRequesterScopePolicy(policy)) return refuse('malformed');
  const { permissions, grantLifetimeSeconds } = request;
  if (!Array.isArray(permissions) || typeof grantLifetimeSeconds !== 'number' || !Number.isSafeInteger(grantLifetimeSeconds) || grantLifetimeSeconds <= 0) {
    return refuse('malformed');
  }
  if (request.renewal !== undefined) return refuse('renewal');
  if (request.context !== undefined) return refuse('context');
  if (permissions.length === 0) return refuse('no-permissions');
  if (grantLifetimeSeconds > policy.maxLifetimeSeconds) return refuse('lifetime');
  for (const permission of permissions) {
    if (!permission || typeof permission !== 'object') return refuse('malformed');
    // Server JSON of unknown shape; each field is type-checked below before use.
    const fields = permission as Record<string, unknown>;
    const { service, path, actions } = fields;
    if (typeof service !== 'string' || typeof path !== 'string' || !Array.isArray(actions) || actions.length === 0 ||
      actions.some((action) => typeof action !== 'string')) {
      return refuse('malformed');
    }
    const sameService = policy.rules.filter((rule) => rule.service === service);
    if (sameService.length === 0) return refuse('service');
    const allowedActions = sameService.filter((rule) => actions.every((action) => rule.actions.includes(action as string)));
    if (allowedActions.length === 0) return refuse('action');
    const space = fields.space;
    const inSpace = allowedActions.filter((rule) => rule.spaces === undefined || (typeof space === 'string' && rule.spaces.includes(space)));
    if (inSpace.length === 0) return refuse('space');
    if (!inSpace.some((rule) => pathFits(rule, path))) return refuse('path');
  }
  return { ok: true };
}
