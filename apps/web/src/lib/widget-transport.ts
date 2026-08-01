// Widget transport.
//
// The single implementation of the parent<->widget postMessage channel used
// by /widget/sign (popup) and /widget/embed/sign (iframe). Enforces:
//
//   1. Strict origin validation. Every incoming MessageEvent is rejected
//      unless `event.origin === configuredOrigin`. The wildcard "*" is
//      NEVER accepted.
//   2. Strict source validation. Every incoming MessageEvent must have
//      `event.source === expectedWindow` (opener for popup, parent for
//      iframe). This prevents a sibling iframe from spoofing messages.
//   3. Correlation via requestId. Every incoming request carries a
//      requestId; responses always echo it. Callers ignoring requestIds
//      cannot mix up concurrent requests.
//   4. Versioned protocol. `protocolVersion` on every request; the widget
//      rejects any protocol it does not recognize.
//   5. Resize messages are targeted at the configured origin. Never "*"
//      even for resize.
//
// The transport is DUMB: it does not interpret request payloads beyond
// the envelope. It surfaces valid requests to a caller-supplied handler.

export interface WidgetTransportOptions {
  /**
   * The origin the widget is opened FROM. Every incoming and outgoing
   * message is validated against this origin.
   *
   * The caller resolves this from `?origin=...` in the URL. If the URL
   * did not carry an origin, the transport MUST NOT be created — refuse
   * to establish a channel with an unknown counterparty rather than
   * accepting "*" as a fallback.
   */
  origin: string;
  /**
   * The container that hosts the widget:
   *   - "popup" — expects `window.opener` to be the counterparty.
   *   - "iframe" — expects `window.parent` to be the counterparty.
   */
  container: "popup" | "iframe";
  /**
   * Called with every well-formed, correlated, in-protocol request. The
   * transport already validated origin, source, and version by the time
   * the handler runs.
   */
  onRequest: (request: WidgetRequest) => void;
  /**
   * Called if the counterparty issued `close`. The caller should reject
   * any pending completion promise as USER_CANCELLED.
   */
  onClose: () => void;
  /**
   * Called for every message that failed origin/source/version validation.
   * Useful for logging suspicious activity; the transport itself drops
   * such messages silently.
   */
  onInvalid?: (reason: InvalidReason, event: MessageEvent) => void;
  /**
   * Optional protocol version override. Defaults to 1.
   */
  protocolVersion?: number;
}

export type InvalidReason =
  | "wrong-origin"
  | "wrong-source"
  | "wrong-protocol-version"
  | "missing-request-id"
  | "unknown-message-type";

export type WidgetMessageType =
  | "openkey:ready"
  | "openkey:sign:request"
  | "openkey:sign:response"
  | "openkey:close"
  | "openkey:resize";

/**
 * Well-formed sign request as delivered to the widget. The transport
 * forwards the entire message envelope (minus the type/requestId/
 * protocolVersion header) as `data` so the widget can extract
 * application-specific fields (`message`, `keyId`, `jwk`, `sessionToken`).
 */
export interface WidgetRequest {
  /** Message type discriminant. */
  type: "openkey:sign:request";
  /** Correlation ID — every response MUST echo this. */
  requestId: string;
  /** Protocol version. */
  protocolVersion: number;
  /**
   * The full message envelope minus the versioning header. Application
   * fields like `message`, `keyId`, `jwk`, `sessionToken` live here.
   */
  data: Record<string, unknown>;
}

export interface WidgetResponseSuccess {
  type: "openkey:sign:response";
  requestId: string;
  protocolVersion: number;
  success: true;
  /**
   * Application response fields (signature, address, signedMessage,
   * selectedActionKeys, permissions). Merged into the outgoing message
   * envelope; must not include `type`, `requestId`, `protocolVersion`,
   * or `success` (transport supplies those).
   */
  data: Record<string, unknown>;
}

export interface WidgetResponseFailure {
  type: "openkey:sign:response";
  requestId: string;
  protocolVersion: number;
  success: false;
  error: { code: string; message: string };
}

export type WidgetResponse = WidgetResponseSuccess | WidgetResponseFailure;

export interface WidgetTransport {
  /** Emit the `openkey:ready` handshake to the counterparty. */
  emitReady: () => void;
  /** Send a response to a completed request. */
  respond: (response: WidgetResponse) => void;
  /** Broadcast a new content height (iframe resize hook). */
  emitResize: (height: number) => void;
  /** Close the channel (caller-side cleanup). */
  destroy: () => void;
}

/**
 * Create a widget transport bound to `opts.origin` and `opts.container`.
 * Throws if the container's expected window is unavailable (e.g. popup
 * mode with no `window.opener`).
 */
export function createWidgetTransport(opts: WidgetTransportOptions): WidgetTransport {
  if (!opts.origin || opts.origin === "*" || opts.origin === "null") {
    throw new Error(
      `Refusing to create widget transport with insecure origin ${JSON.stringify(opts.origin)}. ` +
        "Callers must supply a fully-qualified origin.",
    );
  }
  if (typeof window === "undefined") {
    throw new Error("createWidgetTransport called outside a browser window");
  }

  const expectedWindow: Window | null =
    opts.container === "popup" ? window.opener : window.parent;
  if (!expectedWindow || expectedWindow === window) {
    throw new Error(
      `Widget container "${opts.container}" has no counterparty window.`,
    );
  }
  const protocolVersion = opts.protocolVersion ?? 1;

  const handler = (event: MessageEvent) => {
    if (event.origin !== opts.origin) {
      opts.onInvalid?.("wrong-origin", event);
      return;
    }
    if (event.source !== expectedWindow) {
      opts.onInvalid?.("wrong-source", event);
      return;
    }
    const data = event.data;
    if (!data || typeof data !== "object") return;
    const type = (data as { type?: unknown }).type;
    if (type !== "openkey:sign:request" && type !== "openkey:close") {
      opts.onInvalid?.("unknown-message-type", event);
      return;
    }
    if (type === "openkey:close") {
      opts.onClose();
      return;
    }
    const requestId = (data as { requestId?: unknown }).requestId;
    if (typeof requestId !== "string" || !requestId) {
      opts.onInvalid?.("missing-request-id", event);
      return;
    }
    const version = (data as { protocolVersion?: unknown }).protocolVersion;
    if (typeof version !== "number" || version !== protocolVersion) {
      opts.onInvalid?.("wrong-protocol-version", event);
      return;
    }
    opts.onRequest({
      type: "openkey:sign:request",
      requestId,
      protocolVersion: version,
      data: data as Record<string, unknown>,
    });
  };

  window.addEventListener("message", handler);

  return {
    emitReady() {
      // The parent may lock this down further by expecting an origin here
      // too; the ready message carries no privileged data but MUST still
      // go to the configured origin (never "*").
      expectedWindow.postMessage({ type: "openkey:ready", protocolVersion }, opts.origin);
    },
    respond(response) {
      // Flatten application fields to the top level so parent listeners
      // that read `event.data.signature` (the current SDK wire format)
      // keep working. The transport-defined `type`, `requestId`,
      // `protocolVersion`, and `success` fields always take precedence.
      if (response.success) {
        expectedWindow.postMessage(
          {
            ...response.data,
            type: response.type,
            requestId: response.requestId,
            protocolVersion: response.protocolVersion,
            success: true,
          },
          opts.origin,
        );
      } else {
        expectedWindow.postMessage(
          {
            type: response.type,
            requestId: response.requestId,
            protocolVersion: response.protocolVersion,
            success: false,
            error: response.error,
          },
          opts.origin,
        );
      }
    },
    emitResize(height) {
      expectedWindow.postMessage(
        { type: "openkey:resize", height, protocolVersion },
        opts.origin,
      );
    },
    destroy() {
      window.removeEventListener("message", handler);
    },
  };
}
