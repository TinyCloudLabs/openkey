import { parseEncryptionResource } from '@openkey/capability-review';

/**
 * What a verified requester may ask for. A listed requester keeps its verified name only for a request inside its
 * policy; any other request from the same key is shown as not verified, with the reason from `checkRequesterScope`.
 *
 * A rule covers one service. `path` rules match a resource path under one of the prefixes (a path equal to a prefix,
 * or with an empty, `.` or `..` segment, is outside). `encryption-network` rules match an encryption resource on one
 * network: the network itself, a key or a prefix under it. The owner of the resource is not checked here; the
 * approver can only grant their own.
 */
export type RequesterScopeRule =
  | { kind: 'path'; service: string; actions: readonly string[]; pathPrefixes: readonly string[] }
  | { kind: 'encryption-network'; service: string; actions: readonly string[]; network: string };

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

function isCleanPrefix(prefix: string): boolean {
  return prefix.endsWith('/') && prefix.length > 1 && !hasUnsafeSegment(prefix.slice(0, -1));
}

function hasUnsafeSegment(path: string): boolean {
  if (/[\\\u0000-\u001f\u007f]/.test(path)) return true;
  return path.split('/').some((segment) => segment === '' || segment === '.' || segment === '..');
}

/** Whether a policy is well formed: a bounded lifetime and at least one precise rule. */
export function isRequesterScopePolicy(policy: RequesterScopePolicy): boolean {
  if (!Number.isSafeInteger(policy.maxLifetimeSeconds) || policy.maxLifetimeSeconds <= 0) return false;
  if (!Array.isArray(policy.rules) || policy.rules.length === 0) return false;
  return policy.rules.every((rule) => {
    if (typeof rule.service !== 'string' || rule.service === '') return false;
    if (!Array.isArray(rule.actions) || rule.actions.length === 0 || rule.actions.some((action) => typeof action !== 'string' || action === '')) return false;
    if (rule.kind === 'path') return Array.isArray(rule.pathPrefixes) && rule.pathPrefixes.length > 0 && rule.pathPrefixes.every(isCleanPrefix);
    if (rule.kind === 'encryption-network') return typeof rule.network === 'string' && NETWORK.test(rule.network);
    return false;
  });
}

function pathFits(rule: RequesterScopeRule, path: string): boolean {
  if (rule.kind === 'path') {
    return rule.pathPrefixes.some((prefix) => path.startsWith(prefix) && path.length > prefix.length && !hasUnsafeSegment(path));
  }
  return parseEncryptionResource(path)?.network === rule.network;
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
    if (!allowedActions.some((rule) => pathFits(rule, path))) return refuse('path');
  }
  return { ok: true };
}
