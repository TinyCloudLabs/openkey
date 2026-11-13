export type SignInCancellation = { token: string; requestId: string; origin: string; keyId: string; chainId: number };

/** The app cannot call the cookie-authenticated cancellation API itself. */
export function listenForSignInCancellation(
  current: () => SignInCancellation | undefined,
  beforeCancel: () => void = () => {},
): () => void {
  const receive = async (event: MessageEvent) => {
    const context = current();
    if (!context || event.origin !== context.origin || event.source !== window.opener ||
        event.data?.type !== 'openkey:signin:cancel' || event.data?.protocolVersion !== 1 ||
        event.data?.requestId !== context.requestId || event.data?.token !== context.token) return;
    beforeCancel();
    let cancelled = false;
    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/delegate/signin/cancel`, {
        method: 'POST', credentials: 'include', keepalive: true,
        headers: { 'content-type': 'application/json' }, body: JSON.stringify(context),
      });
      cancelled = response.ok;
    } catch {
      cancelled = false;
    } finally {
      window.opener?.postMessage({ type: 'openkey:signin:cancelled', protocolVersion: 1,
        requestId: context.requestId, cancelled }, context.origin);
    }
  };
  window.addEventListener('message', receive);
  return () => window.removeEventListener('message', receive);
}
