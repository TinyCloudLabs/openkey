export type SpaceSetupPlan = 'setup' | 'auto-sign-off' | 'external-wallet';

export interface SpaceSetupNotice {
  space: string;
  plan: SpaceSetupPlan;
}

export function parseSpaceSetup(value: unknown): SpaceSetupNotice | null {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    !('space' in value) ||
    !('plan' in value)
  ) return null;
  const { space, plan } = value;
  if (
    typeof space !== 'string' ||
    !/^[a-z0-9][a-z0-9-]*$/.test(space) ||
    (plan !== 'setup' && plan !== 'auto-sign-off' && plan !== 'external-wallet')
  ) return null;
  return { space, plan };
}

export function spaceSetupNoticeText(notice: SpaceSetupNotice): string {
  if (notice.plan === 'setup') {
    return `If your ‘${notice.space}’ space in TinyCloud isn't set up yet, approving will also finish setting it up. Auto-Sign is on, so OpenKey does this for you.`;
  }
  if (notice.plan === 'auto-sign-off') {
    return `Your ‘${notice.space}’ space in TinyCloud may not be set up yet. Auto-Sign is off, so approving won't set it up. If it's needed, the app will tell you what to do.`;
  }
  return `Your ‘${notice.space}’ space in TinyCloud may not be set up yet. Approving with an external wallet won't set it up. If it's needed, the app will tell you what to do.`;
}

export function spaceReadinessResult(
  payload: { spaceReady?: unknown; spaceError?: unknown; spacePending?: unknown; spaceId?: unknown },
  notice: SpaceSetupNotice | null,
): { kind: 'ready' | 'pending' | 'unknown' | 'not-ready' | 'failed'; text: string; detail?: string } | null {
  const requested = notice?.space ?? 'requested';
  const space = typeof payload.spaceId === 'string'
    ? payload.spaceId.split(':').at(-1) ?? requested
    : requested;
  if (payload.spaceReady === true) {
    return notice?.plan === 'setup'
      ? { kind: 'ready', text: `Approved. Your ‘${space}’ space in TinyCloud is ready.` }
      : null;
  }
  if (payload.spacePending === true && payload.spaceReady !== false) {
    return { kind: 'pending', text: `Approved. Your ‘${space}’ space in TinyCloud is being set up. This can take a minute. The app will continue when it's ready.` };
  }
  if (payload.spaceReady !== false) {
    return notice
      ? {
          kind: 'unknown',
          text: `Approved, but OpenKey couldn't confirm that your ‘${space}’ space in TinyCloud is set up. The app will tell you what to do.`,
        }
      : null;
  }
  if (typeof payload.spaceError === 'string' && payload.spaceError.length > 0) {
    return {
      kind: 'failed',
      text: `Approved, but setting up your ‘${space}’ space didn't finish. The app will tell you what to do.`,
      detail: payload.spaceError,
    };
  }
  return {
    kind: 'not-ready',
    text: `Approved. Your ‘${space}’ space in TinyCloud isn't set up yet. The app will tell you what to do.`,
  };
}
