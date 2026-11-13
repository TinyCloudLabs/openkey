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
// handler, mis-mapping the CLI selection, signing before a preview
// is ready — surfaces as an unexpected spy call in that test.
//
// The routes themselves are responsible for authentication and other
// non-authorization concerns; those never enter the adapter and never
// enter the parity test.

/** The renewal checkbox (TC-2933), offered only where the requester signed a renewal request. */
export interface RenewalChoice {
  /** The lease the owner chose, in ms from approval; null when the box is unticked. */
  leaseMs: number | null;
  /** The longest lease the requester signed (never more than a year). */
  maxLeaseMs: number;
  onChange: (leaseMs: number | null) => void;
}

/** Transport injected by the CLI (`/delegate`) route. */
export interface CliSigningTransport {
  /**
   * Final approval: the CLI managed/external delegation path. The route
   * captures the delegation JWT and finishes navigation.
   */
  approveDelegate: () => void | Promise<void>;

  /** Back (the review's dismiss control): the CLI's "go back to key selection" navigation. It sends nothing. */
  goBack: () => void;

  /**
   * Decline the approval request (TC-2459). Set only on an approval-request review; the card then offers a Decline
   * button left of Approve. Unset on every other `/delegate` review.
   */
  decline?: () => void | Promise<void>;

  /** True while a decline is being sent. */
  declining?: boolean;

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

  /**
   * How long the approval lasts (TC-2272, TC-2933). `bounded` is true for a signed
   * CLI approval request or a device approval, whose requester signed the
   * longest lifetime it accepts. `onChange` re-issues `/api/delegate/prepare`
   * so the bytes that get signed carry the choice.
   */
  expiry?: {
    chosenMs: number | null;
    bounded: boolean;
    /** The most the requester signed; the shown default can be shorter. Null: the default is the most. */
    maxMs?: number | null;
    onChange: (ms: number | null) => void;
  };
  /** The renewal checkbox; set only on an approval request that signed a renewal request. */
  renewal?: RenewalChoice;
  /**
   * Set while the prepared authorization does not match the visible
   * selection (a narrowing `/prepare` failed or never ran). Approve stays
   * disabled and shows this reason; the selection stays editable so the
   * user can retry.
   */
  approveBlockedReason?: string | null;
  /** A server-declared terminal approval failure; only re-preparation can unblock Approve. */
  approveBlockedByFailure?: boolean;
}

/** Transport injected by the widget popup and iframe routes. */
export interface WidgetSigningTransport {
  /** Set once the server has refused this request for good: Approve is off and this is shown in its place. */
  approveBlockedReason?: string | null;
  /**
   * The TinyCloud node the request names (the sign request's `host`), or empty when it names none. The host
   * approval looks the node key up only there, and only if it is a known node (TC-2309).
   */
  host?: string;

  /**
   * True iff the request is eligible for the server-authoritative
   * narrowing path (versioned request + strict origin + versioned SIWE).
   * When false the adapter routes approval straight to the exact-byte
   * path.
   */
  canUseAuthorizeSign: boolean;

  /** True while a current, unexpired token sealed to the visible selection is held. */
  previewReady: boolean;

  /** Sign the ready sealed preview, or the original bytes on the legacy path. */
  approveAndSign: () => void | Promise<void>;

  /** Owner-initiated retry after a recoverable preview/sign failure; absent while busy. */
  retryPreview?: () => void;

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

  /** True only while the widget is signing. */
  approving: boolean;

  /** Latest error string, or null. */
  error: string | null;
  /** True once the server refused in a way a retry cannot change: Approve stays disabled. */
  refused?: boolean;

  /**
   * How long the approval lasts (TC-2272, TC-2933). Set only when the signing path
   * is the server-authoritative one, which writes the choice into the signed
   * message; unset on the exact-byte path, where the line is not shown.
   * `onChange` must invalidate any approved preview.
   */
  expiry?: {
    chosenMs: number | null;
    onChange: (ms: number | null) => void;
  };
}
