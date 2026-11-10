export type DelegateErrorClassification = 'busy' | 'ended' | 'refresh-once' | 'error';

export function classifyDelegateError(status: number, code: unknown): DelegateErrorClassification {
  if (status === 409) return 'busy';
  if (status === 410) return 'ended';
  if (code === 'context-expired' || code === 'context-not-found') return 'refresh-once';
  return 'error';
}
