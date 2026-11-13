/** Exact browser origins only; opaque requesters receive no legacy messages. */
export function legacySignOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:') ? url.origin : null;
  } catch {
    return null;
  }
}

/** Ready precedes the request, so derive its destination from browser metadata. */
export function legacySignReadyOrigin(): string | null {
  const ancestor = window.parent !== window ? window.location.ancestorOrigins?.[0] : undefined;
  return legacySignOrigin(ancestor || document.referrer);
}
