import { ShareWindowContexts } from './share-window-context';

export const shareWindowContexts = new ShareWindowContexts();
type Session = { id: string; userId: string };
type HookContext = { context?: { session?: { session?: Session } | null } } | null;

/** Better Auth deletes on sign-out; account replacement/rotation retires the prior browser session. */
export function shareWindowSessionHooks(store: ShareWindowContexts) {
  return {
    deleted(session: Session) { store.invalidateSession(session.userId, session.id); },
    created(session: Session, context: HookContext) {
      const previous = context?.context?.session?.session;
      if (previous && (previous.id !== session.id || previous.userId !== session.userId)) {
        store.invalidateSession(previous.userId, previous.id);
      }
    },
    updated(session: Session) { store.invalidateSession(session.userId, session.id); },
  };
}
export const shareWindowAuthHooks = shareWindowSessionHooks(shareWindowContexts);
