import { parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { SiweMessage } from 'siwe';
import { getAddress } from 'viem';

export type TinyCloudManageKeyIdentity = {
  keyId: string;
  address: string;
  chainId: 1;
};

export type TinyCloudManageKeyDecision =
  | { allowed: true }
  | { allowed: false; reason: string };

const MAX_SESSION_TTL_MS = 60 * 60 * 1000;
const MAX_ISSUED_AT_SKEW_MS = 5 * 60 * 1000;

/**
 * This is intentionally a structural gate, not an application permission
 * policy. The tinycloud:manage-key consent boundary is the signed SIWE/ReCap
 * shape; per-client capability ceilings and replay controls are follow-up
 * policy work. Never accept an ordinary text message on this path.
 */
export function validateTinyCloudManageKeyRequest(input: {
  type: unknown;
  chainId: unknown;
  message: unknown;
  identity: TinyCloudManageKeyIdentity;
}): TinyCloudManageKeyDecision {
  if (input.type !== 'siwe') return { allowed: false, reason: 'Only SIWE signing requests are accepted.' };
  if (input.chainId !== input.identity.chainId) {
    return { allowed: false, reason: 'The requested chain does not match the canonical identity.' };
  }
  if (typeof input.message !== 'string' || input.message.length === 0) {
    return { allowed: false, reason: 'The signing message must be a non-empty SIWE string.' };
  }

  let parsed: SiweMessage;
  try {
    parsed = new SiweMessage(input.message);
  } catch {
    return { allowed: false, reason: 'The signing message is not valid SIWE.' };
  }
  if (parsed.version !== '1' || parsed.chainId !== input.identity.chainId) {
    return { allowed: false, reason: 'The SIWE message does not match the canonical chain.' };
  }
  const issuedAt = parsed.issuedAt ? Date.parse(parsed.issuedAt) : Number.NaN;
  const expirationTime = parsed.expirationTime ? Date.parse(parsed.expirationTime) : Number.NaN;
  const now = Date.now();
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expirationTime)
    || issuedAt > now + MAX_ISSUED_AT_SKEW_MS
    || expirationTime <= now
    || expirationTime - issuedAt > MAX_SESSION_TTL_MS) {
    return { allowed: false, reason: 'The SIWE session lifetime is invalid.' };
  }
  try {
    if (getAddress(parsed.address) !== getAddress(input.identity.address)) {
      return { allowed: false, reason: 'The SIWE address does not match the canonical identity.' };
    }
  } catch {
    return { allowed: false, reason: 'The SIWE address is invalid.' };
  }

  let recap: unknown;
  try {
    recap = parseRecapFromSiwe(input.message);
  } catch {
    return { allowed: false, reason: 'The SIWE message does not contain a valid TinyCloud ReCap.' };
  }
  if (!Array.isArray(recap) || recap.length === 0) {
    return { allowed: false, reason: 'The SIWE message must contain TinyCloud ReCap capabilities.' };
  }

  const expectedSpace = `tinycloud:pkh:eip155:${input.identity.chainId}:${getAddress(input.identity.address)}:applications`;
  for (const rawEntry of recap) {
    if (!rawEntry || typeof rawEntry !== 'object' || Array.isArray(rawEntry)) {
      return { allowed: false, reason: 'The TinyCloud ReCap has an invalid capability entry.' };
    }
    const entry = rawEntry as Record<string, unknown>;
    const service = entry.service;
    const space = entry.space;
    const path = entry.path;
    const actions = entry.actions;
    if (typeof service !== 'string' || service.length === 0
      || typeof space !== 'string' || space !== expectedSpace
      || typeof path !== 'string'
      || !Array.isArray(actions) || actions.length === 0
      || !actions.every((action): action is string => typeof action === 'string' && action.startsWith('tinycloud.'))
      || new Set(actions).size !== actions.length) {
      return { allowed: false, reason: 'The TinyCloud ReCap does not target the canonical identity space.' };
    }
  }
  return { allowed: true };
}
