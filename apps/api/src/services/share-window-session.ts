import { shareSessionGeneration, type ShareAuthSessionState } from './share-session-generation';
import { ShareWindowContexts } from './share-window-context';

export const shareWindowContexts = new ShareWindowContexts();
type Session = { id: string; userId: string } & Partial<ShareAuthSessionState>;
type HookContext = { context?: { session?: { session?: Session } | null } } | null;
const previousSessions = new WeakMap<object, Session>();
const invalidators = new Set<(userId: string, sessionId: string, keepGeneration?: string) => void>();
export function registerShareSessionInvalidator(invalidate: (userId: string, sessionId: string, keepGeneration?: string) => void): void {
  invalidators.add(invalidate);
}
/** Set only by the auth before hook after resolving the actual incoming cookie. */
export function rememberSharePreviousSession(context: object, session: Session): void {
  previousSessions.set(context, { id: session.id, userId: session.userId });
}

/** Better Auth hooks invalidate every phase, not just the unclaimed window token. */
export function shareWindowSessionHooks(store: ShareWindowContexts) {
  const invalidate = (session: Session, keepGeneration?: string) => {
    store.invalidateSession(session.userId, session.id, keepGeneration);
    for (const retire of invalidators) retire(session.userId, session.id, keepGeneration);
  };
  return {
    deleted(session: Session) { invalidate(session); },
    created(session: Session, context: HookContext) {
      const previous = (context?.context && previousSessions.get(context.context)) ?? context?.context?.session?.session;
      if (context?.context) previousSessions.delete(context.context);
      if (previous && (previous.id !== session.id || previous.userId !== session.userId)) invalidate(previous);
    },
    updated(session: Session) {
      const generation = typeof session.token === 'string' && session.createdAt instanceof Date && session.expiresAt instanceof Date
        ? shareSessionGeneration(session as ShareAuthSessionState) : undefined;
      invalidate(session, generation);
    },
  };
}
export const shareWindowAuthHooks = shareWindowSessionHooks(shareWindowContexts);
