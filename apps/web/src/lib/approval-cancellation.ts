export type ApprovalCancellation = { token: string; requestId: string; origin: string; keyId: string; chainId?: number };
const protocols = {
  'tinycloud-signin': { prefix: 'openkey:signin', path: '/api/delegate/signin/cancel' },
  'share-create': { prefix: 'openkey:share', path: '/api/delegate/share/cancel' },
} as const;

/** Fixed typed protocols only; the caller cannot supply a signing or cancellation URL. */
export function listenForApprovalCancellation(purpose: keyof typeof protocols,
  current: () => ApprovalCancellation | undefined, beforeCancel: () => void = () => {}): () => void {
  const protocol = protocols[purpose];
  const receive = async (event: MessageEvent) => {
    const context = current();
    if (!context || !window.opener || event.origin !== context.origin || event.source !== window.opener ||
      event.data?.type !== `${protocol.prefix}:cancel` || event.data?.protocolVersion !== 1 ||
      event.data?.requestId !== context.requestId || event.data?.token !== context.token) return;
    beforeCancel();
    let cancelled = false;
    try {
      const { origin, ...shareBody } = context;
      const response = await fetch(`${import.meta.env.VITE_API_URL || ''}${protocol.path}`, {
        method: 'POST', credentials: 'include', keepalive: true,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(purpose === 'share-create' ? shareBody : context),
      });
      cancelled = response.ok && (await response.json()).cancelled === true;
    } catch { cancelled = false; }
    window.opener?.postMessage({ type: `${protocol.prefix}:cancelled`, protocolVersion: 1,
      requestId: context.requestId, cancelled }, context.origin);
  };
  window.addEventListener('message', receive);
  return () => window.removeEventListener('message', receive);
}
