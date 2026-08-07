// OpenKey Nostr signer - browser client for third-party apps.
//
// Structurally separate from the Ethereum/EIP-1193 flows in index.ts:
//  - Nostr identities are secp256k1 Schnorr (BIP-340/NIP-01), never routed
//    through the ECDSA sign/signTypedData paths above.
//  - The OpenKey session and any signing grants never leave the
//    OpenKey-origin iframe. Unlike `openkey:auth:response`, none of the
//    postMessage payloads below ever carry a sessionToken.
//  - Every iframe created here uses a canonical, non-wildcard `host` origin
//    for both `postMessage` targeting and incoming-message verification
//    (`event.origin === host && event.source === iframe.contentWindow`).

/** NIP-01 unsigned event template. */
export interface UnsignedNostrEvent {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

/** A fully signed NIP-01 event, as returned by OpenKey custody signing. */
export interface SignedNostrEvent extends UnsignedNostrEvent {
  id: string;
  sig: string;
}

/** Public descriptor for the user's OpenKey-custodied Nostr identity. Never includes the secret key. */
export interface NostrIdentity {
  keyId: string;
  pubkey: string;
  npub: string;
}

/**
 * Named crypto operations OpenKey custody can perform for a client, on top
 * of event-kind signing. Each is purpose-bound and individually granted;
 * none ever exposes the secret key or a reusable conversation key.
 */
export type NostrOperation = 'nip44_encrypt' | 'nip44_decrypt' | 'nip59_wrap' | 'nip59_unwrap';

/** An unsigned kind-14 DM rumor returned by `nip59Unwrap` - id-addressed but deliberately unsigned. */
export interface NostrRumor {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

/**
 * Capabilities requested up front during `connect`, so the user can approve
 * a client's full working set in one consent card instead of one card per
 * kind. `relayUrl` is required when `kinds` includes a destination-bound
 * kind (22242 relay auth, 24242 Blossom auth, 27235 HTTP auth).
 */
export interface NostrConnectOptions {
  relayUrl?: string;
  kinds?: number[];
  operations?: NostrOperation[];
}

export interface NostrError {
  code: 'USER_CANCELLED' | 'TIMEOUT' | 'INTERACTION_REQUIRED' | 'UNAUTHORIZED' | 'UNKNOWN';
  message: string;
}

type NostrFrameMessage =
  | { type: 'openkey:ready'; protocolVersion: number }
  | { type: 'openkey:close'; requestId: string; protocolVersion: number }
  | { type: 'openkey:resize'; requestId: string; protocolVersion: number; height: number }
  | { type: 'openkey:nostr:show'; requestId: string; protocolVersion: number }
  | { type: 'openkey:nostr:connect:response'; requestId: string; protocolVersion: number; success: true; keyId: string; pubkey: string; npub: string }
  | { type: 'openkey:nostr:connect:response'; requestId: string; protocolVersion: number; success: false; error: NostrError }
  | { type: 'openkey:nostr:sign:response'; requestId: string; protocolVersion: number; success: true; event: SignedNostrEvent }
  | { type: 'openkey:nostr:sign:response'; requestId: string; protocolVersion: number; success: false; error: NostrError }
  | { type: 'openkey:nostr:encrypt:response'; requestId: string; protocolVersion: number; success: true; ciphertext: string }
  | { type: 'openkey:nostr:encrypt:response'; requestId: string; protocolVersion: number; success: false; error: NostrError }
  | { type: 'openkey:nostr:decrypt:response'; requestId: string; protocolVersion: number; success: true; plaintext: string }
  | { type: 'openkey:nostr:decrypt:response'; requestId: string; protocolVersion: number; success: false; error: NostrError }
  | { type: 'openkey:nostr:wrap:response'; requestId: string; protocolVersion: number; success: true; wraps: SignedNostrEvent[] }
  | { type: 'openkey:nostr:wrap:response'; requestId: string; protocolVersion: number; success: false; error: NostrError }
  | { type: 'openkey:nostr:unwrap:response'; requestId: string; protocolVersion: number; success: true; rumor: NostrRumor }
  | { type: 'openkey:nostr:unwrap:response'; requestId: string; protocolVersion: number; success: false; error: NostrError };

const NOSTR_FRAME_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes, matches the Ethereum widget flow
const NOSTR_PROTOCOL_VERSION = 1;

function newRequestId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('Secure request-id generation is unavailable.');
  }
  const bytes = new Uint32Array(4);
  crypto.getRandomValues(bytes);
  return `nostr-${Array.from(bytes, value => value.toString(16)).join('')}`;
}

/**
 * One ephemeral iframe per request. It is mounted off-screen at ~0 size and
 * only expanded into a visible, backdrop-covered modal when the OpenKey
 * widget page explicitly asks for it (`openkey:nostr:show`) - e.g. first-time
 * identity consent, a relay-scoped connect grant, or the first kind:9 message
 * to a new client origin. A silent signing request already covered by an
 * existing grant never sends `show`, so the user sees nothing at all.
 *
 * The hidden/visible states are pure CSS toggles on a container that always
 * holds the same `<iframe>` element - the iframe itself is never removed or
 * reparented, because doing so would reload it (and drop its in-flight
 * request state) in most browsers.
 */
class NostrFrame {
  private root: HTMLDivElement;
  private shadow: ShadowRoot;
  private iframe: HTMLIFrameElement;
  private outer: HTMLDivElement;
  private host: string;
  private messageHandler: (event: MessageEvent) => void = () => {};
  private revealed = false;
  private requestedHeight = 400;
  private viewportHandler = () => {
    this.syncViewport();
    this.applyFrameHeight();
  };

  constructor(host: string, url: string) {
    this.host = host;
    this.root = document.createElement('div');
    this.shadow = this.root.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      :host{all:initial}
      .nf-outer{position:fixed;top:-9999px;left:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none}
      .nf-outer.nf-visible{position:fixed;top:var(--nf-viewport-top,0px);left:var(--nf-viewport-left,0px);width:var(--nf-viewport-width,100vw);height:var(--nf-viewport-height,100dvh);box-sizing:border-box;padding:max(16px,env(safe-area-inset-top)) max(16px,env(safe-area-inset-right)) max(16px,env(safe-area-inset-bottom)) max(16px,env(safe-area-inset-left));overflow:auto;overscroll-behavior:contain;opacity:1;pointer-events:auto;background:rgba(0,0,0,0.42);z-index:999999;display:flex;align-items:center;justify-content:center}
      .nf-card{width:1px;height:1px;overflow:hidden}
      .nf-visible .nf-card{background:#fafafa;width:min(400px,100%);height:auto;max-height:100%;border-radius:16px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.25);overflow:auto;flex:0 1 auto}
      iframe{border:none;width:1px;height:1px;display:block;transition:height 200ms ease}
      .nf-visible iframe{width:100%;height:400px;max-height:100%}
      @media (prefers-reduced-motion:reduce){iframe{transition:none}}
    `;

    this.outer = document.createElement('div');
    this.outer.className = 'nf-outer';
    this.outer.setAttribute('role', 'dialog');
    this.outer.setAttribute('aria-modal', 'true');
    this.outer.setAttribute('aria-label', 'OpenKey approval');
    this.outer.setAttribute('aria-hidden', 'true');

    const card = document.createElement('div');
    card.className = 'nf-card';

    this.iframe = document.createElement('iframe');
    this.iframe.src = url;
    this.iframe.title = 'OpenKey approval';
    this.iframe.setAttribute('allow', 'clipboard-write *; publickey-credentials-get *; publickey-credentials-create *');
    this.iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox');

    card.appendChild(this.iframe);
    this.outer.appendChild(card);
    this.shadow.appendChild(style);
    this.shadow.appendChild(this.outer);
    document.body.appendChild(this.root);

    this.syncViewport();
    window.addEventListener('resize', this.viewportHandler);
    window.visualViewport?.addEventListener('resize', this.viewportHandler);
    window.visualViewport?.addEventListener('scroll', this.viewportHandler);
  }

  onMessage(handler: (data: NostrFrameMessage) => void) {
    this.messageHandler = (event: MessageEvent) => {
      // Canonical, non-wildcard origin only; exact window-identity match.
      if (event.origin !== this.host) return;
      if (event.source !== this.iframe.contentWindow) return;
      handler(event.data as NostrFrameMessage);
    };
    window.addEventListener('message', this.messageHandler);
  }

  reveal() {
    if (this.revealed) return;
    this.revealed = true;
    this.syncViewport();
    this.outer.classList.add('nf-visible');
    this.outer.setAttribute('aria-hidden', 'false');
    this.applyFrameHeight();
  }

  resize(height: number) {
    if (!Number.isFinite(height) || height <= 0) return;
    this.requestedHeight = height;
    if (this.revealed) this.applyFrameHeight();
  }

  private syncViewport() {
    const viewport = window.visualViewport;
    this.outer.style.setProperty('--nf-viewport-top', `${viewport?.offsetTop ?? 0}px`);
    this.outer.style.setProperty('--nf-viewport-left', `${viewport?.offsetLeft ?? 0}px`);
    this.outer.style.setProperty('--nf-viewport-width', `${viewport?.width ?? window.innerWidth}px`);
    this.outer.style.setProperty('--nf-viewport-height', `${viewport?.height ?? window.innerHeight}px`);
  }

  private applyFrameHeight() {
    if (!this.revealed) return;
    const viewportHeight = window.visualViewport?.height ?? window.innerHeight;
    const max = Math.max(1, Math.floor(viewportHeight - 32));
    this.iframe.style.height = `${Math.min(this.requestedHeight, max)}px`;
  }

  postMessage(message: object) {
    this.iframe.contentWindow?.postMessage(message, this.host);
  }

  destroy() {
    window.removeEventListener('message', this.messageHandler);
    window.removeEventListener('resize', this.viewportHandler);
    window.visualViewport?.removeEventListener('resize', this.viewportHandler);
    window.visualViewport?.removeEventListener('scroll', this.viewportHandler);
    this.root.remove();
  }
}

/**
 * Browser client for the OpenKey Nostr custody + signing flow. Get an
 * instance from `OpenKey#nostr` rather than constructing this directly.
 */
export class OpenKeyNostr {
  constructor(private host: string) {}

  /**
   * Get-or-create the user's OpenKey-custodied Nostr identity. Always shows
   * a visible consent card. When `relayUrl`, `kinds`, and/or `operations`
   * are given, the card describes the full requested capability set and a
   * single approval creates one grant covering it - so a client like Buzz
   * can be authorized for its complete working set up front instead of one
   * consent per kind. Never resolves with the secret key; only
   * `keyId`/`pubkey`/`npub`.
   */
  async connect(opts?: NostrConnectOptions): Promise<NostrIdentity> {
    const url = this.widgetUrl();
    return this.run<NostrIdentity>(
      url,
      {
        type: 'openkey:nostr:connect:request',
        relayUrl: opts?.relayUrl,
        kinds: opts?.kinds,
        operations: opts?.operations,
      },
      (data, resolve, reject) => {
        if (data.type !== 'openkey:nostr:connect:response') return false;
        if (data.success) resolve({ keyId: data.keyId, pubkey: data.pubkey, npub: data.npub });
        else reject(data.error);
        return true;
      },
    );
  }

  /**
   * Sign a NIP-01 event template with the user's OpenKey Nostr key. Silent
   * (no visible UI) when an active grant already covers this client origin
   * + key + kind (+ the event's destination, for relay/Blossom/HTTP auth
   * kinds). Otherwise shows a visible consent card before signing.
   *
   * `opts.relayUrl` is a consent hint for destination-bound kinds (22242,
   * 24242, 27235): it tells the approval card which relay the resulting
   * grant should be bound to. It never widens what gets signed - the API
   * independently checks the event's own destination against the grant.
   */
  async signEvent(
    keyId: string,
    event: UnsignedNostrEvent,
    opts?: { relayUrl?: string },
  ): Promise<SignedNostrEvent> {
    const url = this.widgetUrl();
    return this.run<SignedNostrEvent>(
      url,
      { type: 'openkey:nostr:sign:request', keyId, event, relayUrl: opts?.relayUrl },
      (data, resolve, reject) => {
        if (data.type !== 'openkey:nostr:sign:response') return false;
        if (data.success) resolve(data.event);
        else reject(data.error);
        return true;
      },
    );
  }

  /**
   * NIP-44 v2 encrypt-to-self inside OpenKey custody (Buzz encrypted
   * reminders). `peerPubkey` must be the key's own pubkey - the custody API
   * refuses to encrypt to third parties outside a gift wrap. Returns only
   * the ciphertext payload; the conversation key never leaves custody.
   */
  async nip44Encrypt(keyId: string, opts: { peerPubkey: string; plaintext: string }): Promise<string> {
    const url = this.widgetUrl();
    return this.run<string>(
      url,
      { type: 'openkey:nostr:encrypt:request', keyId, peerPubkey: opts.peerPubkey, plaintext: opts.plaintext },
      (data, resolve, reject) => {
        if (data.type !== 'openkey:nostr:encrypt:response') return false;
        if (data.success) resolve(data.ciphertext);
        else reject(data.error);
        return true;
      },
    );
  }

  /**
   * NIP-44 v2 decrypt inside OpenKey custody, from self (reminders) or a
   * peer such as an agent observer (`peerPubkey` = the sender's pubkey).
   * Returns only the bounded plaintext.
   */
  async nip44Decrypt(keyId: string, opts: { peerPubkey: string; payload: string }): Promise<string> {
    const url = this.widgetUrl();
    return this.run<string>(
      url,
      { type: 'openkey:nostr:decrypt:request', keyId, peerPubkey: opts.peerPubkey, payload: opts.payload },
      (data, resolve, reject) => {
        if (data.type !== 'openkey:nostr:decrypt:response') return false;
        if (data.success) resolve(data.plaintext);
        else reject(data.error);
        return true;
      },
    );
  }

  /**
   * NIP-59 gift-wrap a direct message inside OpenKey custody: kind-14
   * rumor, per-target kind-13 seals, kind-1059 wraps signed by fresh
   * ephemeral keys, with the sender's self-wrap first
   * (`wraps.length === recipients.length + 1`). Publish the returned wraps
   * as-is; they are already signed.
   */
  async nip59Wrap(
    keyId: string,
    opts: { content: string; recipients: string[]; createdAt?: number },
  ): Promise<SignedNostrEvent[]> {
    const url = this.widgetUrl();
    return this.run<SignedNostrEvent[]>(
      url,
      {
        type: 'openkey:nostr:wrap:request',
        keyId,
        content: opts.content,
        recipients: opts.recipients,
        createdAt: opts.createdAt,
      },
      (data, resolve, reject) => {
        if (data.type !== 'openkey:nostr:wrap:response') return false;
        if (data.success) resolve(data.wraps);
        else reject(data.error);
        return true;
      },
    );
  }

  /**
   * NIP-59 unwrap a kind-1059 gift wrap addressed to this key. Custody
   * verifies the wrap and seal signatures, recipient binding, sender
   * consistency, and the rumor id before returning the validated kind-14
   * rumor - nothing else ever leaves.
   */
  async nip59Unwrap(keyId: string, wrap: SignedNostrEvent): Promise<NostrRumor> {
    const url = this.widgetUrl();
    return this.run<NostrRumor>(
      url,
      { type: 'openkey:nostr:unwrap:request', keyId, wrap },
      (data, resolve, reject) => {
        if (data.type !== 'openkey:nostr:unwrap:response') return false;
        if (data.success) resolve(data.rumor);
        else reject(data.error);
        return true;
      },
    );
  }

  private widgetUrl(): string {
    const origin = encodeURIComponent(window.location.origin);
    return `${this.host}/widget/embed/nostr/approve?origin=${origin}`;
  }

  private run<T>(
    url: string,
    request: object,
    onData: (data: NostrFrameMessage, resolve: (v: T) => void, reject: (e: NostrError) => void) => boolean,
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const frame = new NostrFrame(this.host, url);
      const requestId = newRequestId();

      const settle = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        fn();
        frame.destroy();
      };

      frame.onMessage((data) => {
        if (!data || typeof (data as { type?: unknown }).type !== 'string') return;

        if (data.type === 'openkey:ready') {
          if (data.protocolVersion !== NOSTR_PROTOCOL_VERSION) return;
          frame.postMessage({ ...request, requestId, protocolVersion: NOSTR_PROTOCOL_VERSION });
          return;
        }
        if (
          data.requestId !== requestId ||
          data.protocolVersion !== NOSTR_PROTOCOL_VERSION
        ) return;
        if (data.type === 'openkey:resize') {
          frame.resize(data.height);
          return;
        }
        if (data.type === 'openkey:nostr:show') {
          frame.reveal();
          return;
        }
        if (data.type === 'openkey:close') {
          settle(() => reject({ code: 'USER_CANCELLED', message: 'Request closed' }));
          return;
        }

        onData(data, (v) => settle(() => resolve(v)), (e) => settle(() => reject(e)));
      });

      const timeout = setTimeout(() => {
        settle(() => reject({ code: 'TIMEOUT', message: 'Nostr request timed out' }));
      }, NOSTR_FRAME_TIMEOUT_MS);
    });
  }
}
