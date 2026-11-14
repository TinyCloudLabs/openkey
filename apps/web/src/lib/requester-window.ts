export type RequesterWindowPurpose = 'share-create' | 'tinycloud-signin';

/** Trusted widget boundary: the observed MessageEvent origin is the only source of requester identity. */
export function acceptRequesterHello(event: Pick<MessageEvent, 'source' | 'origin' | 'data'>, expected: {
  source: MessageEventSource | null;
  requestId: string;
  purpose: RequesterWindowPurpose;
  originHint?: string | null;
}): { origin: string; requestId: string; intent: unknown } | null {
  if (expected.source === null || event.source !== expected.source || !expected.requestId) return null;
  const message = event.data;
  const type = expected.purpose === 'share-create' ? 'openkey:share:hello' : 'openkey:signin:hello';
  if (!message || typeof message !== 'object' || message.type !== type || message.protocolVersion !== 1 ||
    message.purpose !== expected.purpose || message.requestId !== expected.requestId) return null;
  let origin: URL;
  try { origin = new URL(event.origin); } catch { return null; }
  if (origin.protocol !== 'https:' || origin.origin !== event.origin ||
    (expected.originHint != null && expected.originHint !== event.origin) ||
    ('origin' in message && message.origin !== event.origin)) return null;
  if (message.intent && typeof message.intent === 'object' &&
    'origin' in message.intent && message.intent.origin !== event.origin) return null;
  return { origin: event.origin, requestId: expected.requestId, intent: structuredClone(message.intent) };
}
