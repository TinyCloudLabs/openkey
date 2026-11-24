import { STOP_PARTS, approvalStop, fill, stopForReply, type ReplyInput } from '@openkey/sdk/approval-copy';
import type { EthereumKey } from './api';
import { isPasskeyApprovalRefusal } from './approval-passkey';
import { delegateServerMessage } from './delegate-failure-text';
import { ServerReplyError } from './server-reply';
import { isTermsRequired } from './terms';
import { termsRefused } from './terms-gate';

export class ApprovalReplyError extends Error {
  constructor(readonly status: number, readonly code?: unknown, readonly detail?: string, message = `HTTP ${status}`) {
    super(message);
  }
}

/** Both signing routes answer sign_failed after releasing the claimed handoff. */
export function releasedSigningCancellation(cause: unknown, cancel: () => Promise<unknown>) {
  if (!(cause instanceof ApprovalReplyError) || cause.code !== 'sign_failed') return;

  let pending: Promise<void> | undefined;
  return () => pending ??= new Promise<void>((resolve) => {
    const timeout = setTimeout(resolve, 300);
    const finish = () => {
      clearTimeout(timeout);
      resolve();
    };
    void cancel().then(finish, finish);
  });
}

export function stopForApprovalError(cause: unknown, context: ReplyInput) {
  if (cause instanceof ServerReplyError) return approvalStop('S27', { ...context, status: cause.status });
  if (cause instanceof ApprovalReplyError) {
    return stopForReply({ ...context, status: cause.status, code: cause.code, detail: cause.detail });
  }
  if (cause instanceof Error && 'status' in cause && typeof cause.status === 'number') {
    return stopForReply({ ...context, status: cause.status, code: 'code' in cause ? cause.code : undefined });
  }
  return approvalStop('S26', context);
}

export async function readHandoffReply(response: Response, valid?: (reply: Record<string, unknown>) => boolean) {
  const body: unknown = await response.json().catch(() => null);
  const reply = body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : null;
  if (!response.ok) {
    if (isTermsRequired(response.status, reply)) termsRefused();
    const passkeyMessage = isPasskeyApprovalRefusal(reply) && typeof reply?.error === 'string' ? reply.error : undefined;
    throw new ApprovalReplyError(response.status, reply?.code, delegateServerMessage(reply), passkeyMessage);
  }
  if (!reply || (valid && !valid(reply))) throw new ServerReplyError(response.status);
  return reply;
}

export function shortWallet(address: string) {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function stopKeyName(key: EthereumKey) {
  return key.label ?? fill(STOP_PARTS.keyName, { index: key.keyIndex });
}

export function compareWallets(keys: EthereumKey[]) {
  return keys.map((key) => ({ address: shortWallet(key.address), name: stopKeyName(key) }));
}
