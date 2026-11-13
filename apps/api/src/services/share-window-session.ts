import { ShareWindowContexts } from './share-window-context';

export const shareWindowContexts = new ShareWindowContexts();
type Session = { id: string; userId: string };
type HookContext = { context?: { session?: { session?: Session } | null } } | null;
const previousSessions = new WeakMap<object, Session>();
const invalidators = new Set<(userId: string, sessionId: string) => void>();
export function registerShareSessionInvalidator(invalidate: (userId: string, sessionId: string) => void): void {
  invalidators.add(invalidate);
}
/** Set only by the auth before hook after resolving the actual incoming cookie. */
export function rememberSharePreviousSession(context: object, session: Session): void {
  previousSessions.set(context, { id: session.id, userId: session.userId });
}

/** Better Auth hooks invalidate every phase, not just the unclaimed window token. */
export function shareWindowSessionHooks(store: ShareWindowContexts) {
  const invalidate = (session: Session) => {
    store.invalidateSession(session.userId, session.id);
    for (const retire of invalidators) retire(session.userId, session.id);
  };
  return {
    deleted: invalidate,
    created(session: Session, context: HookContext) {
      const previous = (context?.context && previousSessions.get(context.context)) ?? context?.context?.session?.session;
      if (context?.context) previousSessions.delete(context.context);
      if (previous && (previous.id !== session.id || previous.userId !== session.userId)) invalidate(previous);
    },
    updated: invalidate,
  };
}
export const shareWindowAuthHooks = shareWindowSessionHooks(shareWindowContexts);
