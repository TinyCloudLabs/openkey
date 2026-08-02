// Substantive-adapter transport interfaces.
//
// The three OpenKey signing surface adapters (CLI, popup, iframe) each own
// the surface-specific glue that used to live in the route's inline
// `onApprove` / `onCancel` / `onSelectionChange` lambdas. The route is
// responsible only for building the initial authorization model and
// providing a `transport` implementation that reaches out to that
// surface's completion path (delegate/callback, popup postMessage,
// iframe transport response).
//
// Because the adapter owns the glue, the parity test can mount the real
// adapter component with a fixture model and a spy transport, then
// dispatch real DOM keyboard events. A route-specific wiring bug —
// dropping `invalidatePreview` from the widget adapter's selection
// handler, mis-mapping the CLI selection, forgetting to call the preview
// path when supported — surfaces as a missing spy call in that test.
//
// The routes themselves are responsible for authentication and other
// non-authorization concerns; those never enter the adapter and never
// enter the parity test.

/** Transport injected by the CLI (`/delegate`) route. */
export interface CliSigningTransport {
  /**
   * Final approval: the CLI managed/external delegation path. The route
   * captures the delegation JWT and finishes navigation.
   */
  approveDelegate: () => void | Promise<void>;

  /** Cancel: the CLI's "go back to key selection" navigation. */
  goBack: () => void;

  /**
   * Called whenever the user narrows the selection. The route is
   * responsible for mapping the review selection back to canonical action
   * keys and re-issuing `/api/delegate/prepare` so the server-side subset
   * validation still runs.
   *
   * The adapter passes the CURRENT `Set<string>` of action IDs; the route
   * MUST NOT trust the adapter's own selection state to reach this call.
   */
  updateSelection: (nextSelection: Set<string>) => void | Promise<void>;

  /** True while the CLI is delegating or updating permissions. */
  approving: boolean;

  /** Latest error string, or null. */
  error: string | null;
}

/** Transport injected by the widget popup and iframe routes. */
export interface WidgetSigningTransport {
  /**
   * True iff the request is eligible for the server-authoritative
   * narrowing path (versioned request + strict origin + versioned SIWE).
   * When false the adapter routes approval straight to the exact-byte
   * path.
   */
  canUseAuthorizeSign: boolean;

  /**
   * True after the server has prepared exact bytes and sealed them to the
   * current selection. The adapter keeps rendering the shared approval
   * content, but the next approval now consumes that preview instead of
   * requesting another one.
   */
  previewReady: boolean;

  /**
   * Server-authoritative narrowing path: fetch a preview of the exact
   * bytes the server would sign for the current selection. The route puts
   * those bytes back into the shared review model; the adapter fires this
   * only when `canUseAuthorizeSign` is true and no preview is ready.
   */
  requestPreview: () => void | Promise<void>;

  /**
   * Exact-byte fall-through: the legacy widget path signs the caller's
   * original bytes verbatim. The adapter fires this when
   * `canUseAuthorizeSign` is false.
   */
  approveAndSign: () => void | Promise<void>;

  /** Cancel: send the widget cancel response and close the surface. */
  cancel: () => void;

  /**
   * Called on every user selection edit with the up-to-date action-ID
   * set. The route mirrors this into its own `reviewSelection` so the
   * completion payloads (`effectivePermissions`, `selectedActionKeys`)
   * see the current selection.
   */
  onSelectionEdited: (nextSelection: Set<string>) => void;

  /**
   * Invalidate any approved preview when the selection changes. The
   * adapter fires this on EVERY selection change (regardless of
   * `canUseAuthorizeSign`) — the route is responsible for making it a
   * safe no-op on the legacy path.
   */
  invalidatePreview: () => void;

  /** True while the widget is previewing or signing. */
  approving: boolean;

  /** Latest error string, or null. */
  error: string | null;
}
