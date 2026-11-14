export interface ShareApprovalIntent {
  approvalNonce: string;
  session: { siwe: string; signature: string; publicJwk: Record<string, unknown> };
  expiresAt: string;
  permissions?: { service: 'tinycloud.kv'; space: string; path: string; actions: ('tinycloud.kv/get' | 'tinycloud.kv/metadata')[] }[];
}
export interface ShareApprovalIdentity {
  requestId: string; shareId: string; ownerDid: string; sessionDid: string; origin: string;
  intentDigest: string; expiresAt: number; prepared: { siwe: string };
}
export interface ShareApprovalResult {
  purpose: 'share-create'; requestId: string; shareId: string; ownerDid: string; sessionDid: string;
  origin: string; prepared: { siwe: string }; signature: string;
}
export type ShareApprovalVerifier = (input: { result: ShareApprovalResult; identity: Readonly<ShareApprovalIdentity>;
  request: ShareApprovalIntent; origin: string }) => Promise<boolean>;

/** The TinyCloud consumer supplies its cryptographic result verifier; no caller-chosen share id exists. */
export function beginShareApprovalTransport(options: {
  host: string; popup: Window; intent: ShareApprovalIntent; verify: ShareApprovalVerifier;
  available: () => Promise<boolean>;
  signExternal: (message: string, address: string) => Promise<string>;
  registerCancel: (cancel: () => Promise<void>) => void;
  unregisterCancel: (cancel: () => Promise<void>) => void;
}) {
  const popup = options.popup;
  const outerRequestId = crypto.randomUUID();
  const origin = window.location.origin;
  const intent = structuredClone(options.intent);
  if (!/^[0-9a-f]{64}$/.test(intent.approvalNonce) || Object.keys(intent).some(key => !['approvalNonce', 'session', 'expiresAt', 'permissions'].includes(key))) {
    popup.close(); throw new Error('Invalid new-share intent');
  }
  let identity: Readonly<ShareApprovalIdentity> | undefined;
  let token: string | undefined;
  let cancelled = false;
  let started = false;
  const cancel = async () => {
    cancelled = true;
    options.unregisterCancel(cancel);
    if (identity && token && !popup.closed) {
      for (let attempt = 0; attempt < 2; attempt++) {
        const confirmed = await new Promise<boolean>(resolve => {
          const finish = (value: boolean) => { clearTimeout(timer); window.removeEventListener('message', receive); resolve(value); };
          const receive = (event: MessageEvent) => {
            if (event.origin === options.host && event.source === popup && event.data?.protocolVersion === 1 &&
              event.data?.type === 'openkey:share:cancelled' && event.data?.requestId === identity!.requestId) {
              finish(event.data.cancelled === true);
            }
          };
          const timer = setTimeout(() => finish(false), 2000);
          window.addEventListener('message', receive);
          popup.postMessage({ type: 'openkey:share:cancel', protocolVersion: 1,
            requestId: identity!.requestId, token }, options.host);
        });
        if (confirmed || popup.closed) break;
      }
    }
    popup.close();
  };
  options.registerCancel(cancel);
  return { cancel, authorize: async (): Promise<ShareApprovalResult> => {
    if (started || cancelled) throw new Error('Share approval already used');
    started = true;
    try {
      if (!await options.available()) throw new Error("OpenKey new-share approval unavailable");
      if (cancelled || popup.closed) throw new Error("Share approval cancelled");
      return await new Promise<ShareApprovalResult>((resolve, reject) => {
        let verifying = false;
        let externalSigning = false;
        const cleanup = () => { clearTimeout(timeout); clearInterval(poll); window.removeEventListener('message', receive); };
        const fail = (cause: unknown) => { cleanup(); reject(cause instanceof Error ? cause : new Error(String(cause))); };
        const receive = async (event: MessageEvent) => {
          if (event.origin !== options.host || event.source !== popup || event.data?.protocolVersion !== 1) return;
          const data = event.data;
          if (data.type === 'openkey:share:ready' && data.requestId === outerRequestId && data.purpose === 'share-create') {
            popup.postMessage({ type: 'openkey:share:hello', protocolVersion: 1,
              purpose: 'share-create', requestId: outerRequestId, intent }, options.host);
            return;
          }
          if (data.outerRequestId !== outerRequestId || cancelled) return;
          try {
            if (data.type === 'openkey:share:error') throw new Error('Share approval refused');
            if (data.type === 'openkey:share:preview') {
              if (identity) throw new Error('Share preview changed');
              const preview = data.preview;
              if (!preview || !/^[A-Za-z0-9_-]{43}$/.test(preview.requestId) || !/^[0-9a-f]{32}$/.test(preview.shareId) ||
                !/^[0-9a-f]{64}$/.test(preview.intentDigest) || preview.origin !== origin ||
                typeof preview.prepared?.siwe !== 'string' || typeof preview.assertion?.token !== 'string') throw new Error('Invalid Share preview');
              identity = Object.freeze({ requestId: preview.requestId, shareId: preview.shareId,
                ownerDid: preview.ownerDid, sessionDid: preview.sessionDid, origin: preview.origin,
                intentDigest: preview.intentDigest, expiresAt: preview.expiresAt,
                prepared: Object.freeze({ siwe: preview.prepared.siwe }) });
              token = preview.assertion.token;
              return;
            }
            if (data.type === 'openkey:share:sign') {
              if (externalSigning || !identity || data.requestId !== identity.requestId || data.intentDigest !== identity.intentDigest ||
                data.message !== identity.prepared.siwe || typeof data.address !== 'string' ||
                identity.ownerDid.toLowerCase().split(':').at(-1) !== data.address.toLowerCase()) throw new Error('Share signer changed');
              externalSigning = true;
              const signature = await options.signExternal(identity.prepared.siwe, data.address);
              if (cancelled || popup.closed) throw new Error('Share approval cancelled');
              popup.postMessage({ type: 'openkey:share:signature', protocolVersion: 1, outerRequestId,
                requestId: identity.requestId, intentDigest: identity.intentDigest, signature }, options.host);
              return;
            }
            if (data.type !== 'openkey:share:result') return;
            if (!identity || verifying) throw new Error('Unexpected Share result');
            verifying = true;
            const result = structuredClone(data.result) as ShareApprovalResult;
            if (await options.verify({ result, identity, request: structuredClone(intent), origin }) !== true || cancelled || popup.closed) {
              throw new Error('Share verification refused');
            }
            token = undefined;
            cleanup(); resolve(result);
          } catch (cause) { fail(cause); }
        };
        const timeout = setTimeout(() => fail(new Error('Share approval expired')), 300_000);
        const poll = setInterval(() => { if (cancelled || popup.closed) fail(new Error('Share approval cancelled')); }, 100);
        window.addEventListener('message', receive);
        popup.location.href = `${options.host}/widget/share?requestId=${encodeURIComponent(outerRequestId)}`;
      });
    } finally { await cancel(); }
  } };
}
