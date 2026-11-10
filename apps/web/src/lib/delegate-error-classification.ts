export type DelegateErrorClassification = 'busy' | 'ended' | 'refresh-once' | 'panel-after-failed-refresh' | 'error';

export function classifyDelegateError(status: number, code: unknown, refreshAttempted = false): DelegateErrorClassification {
  if (status === 409) return 'busy';
  if (status === 410) return 'ended';
  if (code === 'context-expired' || code === 'context-not-found') {
    return refreshAttempted ? 'panel-after-failed-refresh' : 'refresh-once';
  }
  return 'error';
}
