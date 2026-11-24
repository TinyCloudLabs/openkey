<script lang="ts">
  // SigningApproval — the single canonical content view for every OpenKey
  // authorization surface.
  //
  // Structural rules (from the merge-readiness contract):
  //   1. Default view is small, deterministic, and derived from the actual
  //      SIWE/ReCap request PLUS explicitly provenance-labelled manifest
  //      data. It surfaces the requester, a short list of understandable
  //      statements (from statements.ts), and a sensitive count when the
  //      listed rows mix Sensitive badges with unbadged rows.
  //   2. A single top-level `<details>` labelled `Advanced details` contains:
  //      requester, verified browser origin, manifest name/appId/digest with
  //      HONEST trust/provenance label, reason (only when present), signing
  //      identity, the "How long it lasts" choices (where the surface lets the
  //      owner change the time; the card keeps only the one expiry line),
  //      categorized exact-grant list, Edit/Reset controls, the
  //      full raw message as `<pre>` (`user-select: text`; line feeds are line
  //      breaks, other control and invisible characters and runs of spaces are
  //      escaped by `renderSiweLiteral`) plus a
  //      `Copy text` button that copies `model.rawMessage` UNMODIFIED.
  //   3. `originWarning` and `domainWarning` render distinctly — a concrete
  //      but mismatched origin MUST NOT hide the SIWE-domain mismatch.
  //   4. Approve is blocked when `model.protocol === "malformed-recap"`.
  //   5. `manifestLabel/appId/digest` render only under a truthful
  //      `metadataTrust.status` — never claim `verified` for
  //      caller-supplied metadata.
  //
  // It does NOT:
  //   - open popups or iframes
  //   - resolve wallets or select keys
  //   - decide authentication mode
  //   - talk to the API
  //   - size itself for a specific transport
  //   - branch on "CLI" / "popup" / "iframe" — those are container-only
  //
  // Surface context (TC-659): every surface gets the same header, reason,
  // summary, Advanced details, error line and buttons. A surface passes
  // only its own facts through `context` (the CLI's node, return target and
  // acknowledgements), rendered in one fixed slot under the header, and
  // `showSigner` when the user picked one of several keys. Surfaces must not
  // render their own copy of `error`: it is shown once, above the buttons.

  import { tick, type Snippet } from "svelte";
  import type {
    CapabilityAction,
    CapabilityGrant,
    CapabilityReviewModel,
  } from "@openkey/capability-review";
  import { formatLocalAccessEnd } from "$lib/access-end";
  import {
    APP_KEY_GROUP_NOTE,
    appDisplayName,
    appKeyAccessStatement,
    appKeyIdentity,
    appRequestingLine,
    FAMILY_LABEL,
    appKeyNotGrantableStatements,
    buildRenderPlan,
    buildSummaryStatements,
    type SummaryStatement,
    RENEWAL_ONLY_COPY,
    grantIsAppKeyDecrypt,
    sensitiveSummaryCount,
    grantHeading,
    protocolHeadline,
    PROTOCOL_HINT,
    SIWE_WITHOUT_EXPIRY,
    NAMED_SECRET_DECRYPT_ROW,
    oneNamedSecret,
    sensitiveRowsCallout,
    abbreviateDid,
    abbreviateSpaceId,
    readSpaceHostFacts,
    renderSiweLiteral,
    splitStatementCode,
    elevatedAbilityVerb,
    elevatedCard,
    elevatedKindOf,
    elevatedNotApprovedRow,
    elevatedRejectedCountAnnouncement,
    elevatedWhere,
    elevatedWhereText,
    masterKeyRejectNote,
    MASTER_KEY_TITLE,
    allSecretsAbility,
    allSecretsCard,
    allSecretsReach,
    grantDecryptsOneSecret,
    secretLifetimeCapApplies,
    SECRET_GRANT_MAX_SECONDS,
    type ElevatedKind,
  } from "@openkey/capability-review";
  import type { PeerRecognitionState } from "$lib/host-peer-recognition";
  import { NETWORK_DECRYPT_CAP } from "$lib/network-decrypt-cap";
  import ApprovalExpiryChooser from "$lib/components/signing/approval-expiry-chooser.svelte";
  import ApprovalExpiryControl from "$lib/components/signing/approval-expiry-control.svelte";
  import ElevatedWarning from "$lib/components/signing/elevated-warning.svelte";
  import ClaimedPresentation from "$lib/components/signing/claimed-presentation.svelte";
  import type { ClaimedPresentationView } from "$lib/claimed-presentation";
  import type { RenewalChoice, ShortenOnlyExpiry } from "$lib/components/signing/signing-adapter-types";
  import type { ApproveVisibility } from "$lib/approve-visibility";
  import {
    ONCE_DEFAULT_EXPIRY_MS,
    accessLastsLine,
    cappedAskMs,
    formatDurationWithEnd,
    onceCautionLine,
    onceDefaultExpiryMs,
    onceLongerChoice,
    remainingAccessMs,
    requestedExpiryMs,
  } from "$lib/approval-expiry";
  import { isOnceTier, onceReachOf, renewalNeedsSensitiveConfirm } from "$lib/renewal-default";

  interface Props {
    model: CapabilityReviewModel;
    selection: Set<string>;
    editing: boolean;
    approving?: boolean;
    error?: string | null;
    /** Server-supplied reason for `error`; shown as plain text in a closed "Details" disclosure under it. */
    errorDetail?: string | null;
    /**
     * When set, Approve is disabled and this reason is shown; unlike
     * `approving`, the selection controls stay usable so the caller can
     * re-prepare.
     */
    approveBlockedReason?: string | null;
    /** Disable Approve after an API-declared terminal failure until re-preparation succeeds. */
    approveBlockedByFailure?: boolean;
    /** Disable Approve while an embedding host is applying the review layout. */
    layoutBlocked?: boolean;
    stickyActions?: boolean;
    /** The server refused in a way a retry cannot change: Approve stays disabled (Cancel still works). */
    refused?: boolean;
    /** Disable only Approve while the route prepares the current preview. */
    previewPending?: boolean;
    approveText?: string;
    cancelText?: string;
    /**
     * Offered only on the approval-request review (TC-2459): a Decline button left of Approve, and the dismiss
     * control becomes a text link above the pair. Widget surfaces leave it unset and keep their Cancel button.
     */
    onDecline?: () => void;
    declineText?: string;
    /** A decline is being sent: Decline, Approve and the dismiss control are off, so it cannot go twice. */
    declining?: boolean;
    /** Surface-specific context rendered in a fixed slot under the header. */
    context?: Snippet;
    /** Show which key signs; for users who chose one of several keys. */
    showSigner?: boolean;
    /**
     * Lookup state for the node key on a host approval. Leave unset where the
     * key on the request is not a node (the `/delegate` session grant): the
     * view then shows the space only.
     */
    peerRecognition?: PeerRecognitionState | null;
    /**
     * The approval expiry the user chose, in ms from approval; null keeps what
     * the app asked for. The line shows only on surfaces that pass
     * `onExpiryChange`, i.e. those whose signing path writes the choice into
     * the signed message.
     */
    expiryMs?: number | null;
    onExpiryChange?: (ms: number | null) => void;
    /**
     * True where the requester signed the longest time it accepts (signed CLI
     * and device requests): the picker then offers nothing longer than asked.
     */
    expiryBounded?: boolean;
    /** With `expiryBounded`: the most the requester signed, when that is more than the default it asked for. */
    expiryMaxMs?: number | null;
    shortenOnlyExpiry?: ShortenOnlyExpiry | null;
    /**
     * Set by the surfaces that write the choice into the signed message: a one-time approval that can open all
     * secrets or all encrypted data and asks for longer than an hour starts at one hour, until the owner picks a
     * time.
     */
    onceExpiryDefault?: boolean;
    /**
     * Set by the popup and frame pages: the server limits an owner's pick on a one-time approval to 7 days, whatever
     * the web cap flags say, so the one-time choice offers no more.
     */
    oncePickCapped?: boolean;
    /** The renewal checkbox (TC-2933); set only where the requester signed a renewal request. */
    renewal?: RenewalChoice | null;
    /**
     * The warning screen for extra permissions (TC-2927): decrypt, key creation, or blocking and unblocking keys on the
     * encryption network, or on keys outside the app's own area. Set only by the signing pages that carry the owner's decision to the server.
     * Approve opens the screen first when the selection carries one; `splittable` is false where the request cannot be
     * narrowed (exact bytes): approve or cancel it whole. `onDecide` gets the action ids the owner allowed.
     */
    elevated?: { splittable: boolean; onDecide: (allowed: string[]) => void } | null;
    /** Reports whether the Approve button is in plain view; see `approve-visibility.ts`. */
    approveVisibility?: ApproveVisibility | null;
    /** The app's own words about a plain `signMessage()` request (name, who it is for, reason); shown under the requester line. */
    claimed?: ClaimedPresentationView | null;
    /**
     * The words for a request for one named secret, set only by the one-tap approval: its heading, the line
     * under it, and the note under the decrypt row. Used while the selection is exactly that request.
     */
    oneSecret?: { headline: string; hint: string; decryptNote: string } | null;
    /**
     * Set only by a one-tap approval whose signer OpenKey can't name: the "Requested by" value, with a line under
     * it, while the request names no requester.
     */
    unverifiedRequester?: { name: string; line: string } | null;
    /**
     * The app a sign-in is for, set by a surface that took the name from OpenKey's own list of requesters and never
     * from the request (the CLI link page). A manifest name or origin host the request carries is read from the model.
     */
    signInApp?: string | null;
    onApprove: () => void;
    onCancel: () => void;
    onRetry?: () => void;
    onSelectionChange: (next: Set<string>) => void;
    onEditingChange: (next: boolean) => void;
  }

  let {
    model,
    selection,
    editing,
    approving = false,
    error = null,
    errorDetail = null,
    approveBlockedReason = null,
    approveBlockedByFailure = false,
    layoutBlocked = false,
    stickyActions = false,
    refused = false,
    previewPending = false,
    approveText = "Approve",
    cancelText = "Cancel",
    onDecline,
    declineText = "Decline",
    declining = false,
    context,
    showSigner = false,
    peerRecognition = null,
    expiryMs = null,
    onExpiryChange,
    expiryBounded = false,
    expiryMaxMs = null,
    shortenOnlyExpiry = null,
    onceExpiryDefault = false,
    oncePickCapped = false,
    renewal = null,
    elevated = null,
    approveVisibility = null,
    claimed = null,
    oneSecret = null,
    signInApp = null,
    unverifiedRequester = null,
    onApprove,
    onCancel,
    onRetry,
    onSelectionChange,
    onEditingChange,
  }: Props = $props();

  const shortSignerAddress = $derived(
    `${model.signer.address.slice(0, 6)}...${model.signer.address.slice(-4)}`,
  );
  const renderPlan = $derived(buildRenderPlan(model.permissions));
  const requestedExpiry = $derived(
    requestedExpiryMs(model.immutable?.issuedAt, model.immutable?.expirationTime),
  );
  // Where the surface signs the message as written, the access lasts until its own Expiration Time.
  const signedAsWrittenMs = $derived(
    model.protocol === "tinycloud-siwe-recap" ? remainingAccessMs(model.expiry) : null,
  );
  const permissionSections = $derived.by(() => {
    const reviewGrants = renderPlan
      .filter((bucket) => bucket.severity !== "standard")
      .flatMap((bucket) => bucket.grants);
    const standardGrants = renderPlan.find(
      (bucket) => bucket.severity === "standard",
    )?.grants ?? [];

    return [
      ...(reviewGrants.length > 0
        ? [{
            key: "review",
            severity: "review" as const,
            heading: "Permissions",
            hint: "Sensitive access is shown first.",
            grants: reviewGrants,
            defaultOpen: true,
          }]
        : []),
      ...(standardGrants.length > 0
        ? [{
            key: "standard",
            severity: "standard" as const,
            heading: "Standard permissions",
            hint: "Routine bootstrap access.",
            grants: standardGrants,
            defaultOpen: false,
          }]
        : []),
    ];
  });
  const isEditable = $derived(
    model.protocol === "tinycloud-siwe-recap" &&
    model.permissions.some((grant) => grant.actions.some((action) => action.editable)),
  );
  const isMalformedRecap = $derived(model.protocol === "malformed-recap");

  // Summary copy and the sensitive count describe only actions the user is
  // currently approving. Advanced details deliberately retains the baseline
  // grants so Edit/Reset can re-add a removed action, but a removed decrypt or
  // secret action must never survive in the top-level final review.
  const renewalOn = $derived(renewal?.leaseMs != null);
  const selectedWithRenewal = $derived(
    model.permissions.flatMap((grant) => {
      const actions = grant.actions.filter((action) => selection.has(action.id));
      return actions.length > 0 ? [{ ...grant, actions }] : [];
    }),
  );

  const selectedGrants = $derived(
    renewalOn ? selectedWithRenewal : selectedWithRenewal.filter((grant) => !grant.renewalOnly),
  );
  const renewalOnlyStatements = $derived(
    buildSummaryStatements(selectedWithRenewal.filter((grant) => grant.renewalOnly)),
  );
  const summaryStatements = $derived(
    buildSummaryStatements(selectedGrants.filter((grant) => !grant.renewalOnly)),
  );
  const secretStatements = $derived(summaryStatements.filter((statement) => statement.secret !== undefined));
  const groupSecrets = $derived(secretStatements.length >= 4);
  const effectiveStatements = $derived(
    renewalOn && renewalOnlyStatements.length > 0 ? buildSummaryStatements(selectedGrants) : summaryStatements,
  );
  const sensitiveCount = $derived(sensitiveSummaryCount(effectiveStatements));
  const renewalSensitive = $derived(renewalNeedsSensitiveConfirm(selectedWithRenewal));
  const oneSecretShown = $derived(oneSecret !== null && oneNamedSecret(selectedGrants) !== null);
  const hint = $derived(oneSecretShown ? oneSecret!.hint : PROTOCOL_HINT[model.protocol]);

  // A signed request that can open all secrets or all encrypted data starts as a whole at one hour or less.
  const onceGrants = $derived(shortenOnlyExpiry ? model.permissions : selectedGrants);
  const onceTier = $derived(isOnceTier(onceGrants));
  const onceDefaultMs = $derived(
    onceExpiryDefault && onExpiryChange && model.protocol === "tinycloud-siwe-recap"
      ? onceDefaultExpiryMs(onceTier, shortenOnlyExpiry?.startMs ?? requestedExpiry)
      : null,
  );
  // A grant on secret keys made outside a signed approval request (popup, frame, pasted link) lasts 7 days at most,
  // and so does a whole network's decrypt where the network cap is on: the server clamps a longer one, so
  // the screen offers no more. A signed request has its own maximum.
  const secretCapMs = $derived(
    !shortenOnlyExpiry && secretLifetimeCapApplies(model.permissions, { networkDecrypt: NETWORK_DECRYPT_CAP })
      ? SECRET_GRANT_MAX_SECONDS * 1000
      : null,
  );
  const unsignedMaxMs = $derived.by(() => {
    const bounded = expiryBounded ? (expiryMaxMs ?? requestedExpiry) : null;
    return secretCapMs === null ? bounded : Math.min(bounded ?? secretCapMs, secretCapMs);
  });
  // A signed request may be made longer than its start, up to the maximum its requester signed, unless it
  // can open all secrets or all encrypted data: then the start (the requester's own suggestion) stays the most.
  const expiryFoldMaxMs = $derived(shortenOnlyExpiry
    ? (onceTier ? shortenOnlyExpiry.startMs : Math.max(expiryMaxMs ?? 0, shortenOnlyExpiry.startMs))
    : unsignedMaxMs,
  );
  let ownerChoseExpiry = $state(false);
  let onceDefaultSent = $state(false);
  // Until the default has been applied the expiry line and its note are not shown and Approve waits, so neither a
  // screen reader nor a click meets the app's longer time first (the surface re-prepares with the hour at once).
  const onceDefaultPending = $derived(
    onceDefaultMs !== null && !ownerChoseExpiry && expiryMs === null && (shortenOnlyExpiry !== null || !onceDefaultSent),
  );
  // The default starts once the tier holds and the owner has picked nothing. Leaving the tier (the broad access is
  // removed) drops only the one-hour default, so the app's ask applies again; the owner's own pick is kept, and
  // adding the access back starts at one hour again only when the owner had picked nothing. A pick of "what the app
  // asked" is the app's ask itself and ends with the tier.
  $effect(() => {
    if (approving || previewPending || !onExpiryChange) return;
    if (onceDefaultMs === null) {
      if (!onceDefaultSent) return;
      onceDefaultSent = false;
      if (ownerChoseExpiry) {
        if (expiryMs === null) ownerChoseExpiry = false;
        return;
      }
      if (expiryMs === ONCE_DEFAULT_EXPIRY_MS) onExpiryChange(null);
      return;
    }
    if (ownerChoseExpiry) return;
    if (expiryMs === null && !onceDefaultSent) {
      onceDefaultSent = true;
      onExpiryChange(onceDefaultMs);
    }
  });
  // An app's longer time on secret keys starts at the 7 days the server allows (the one-hour start, where it applies,
  // is shorter and goes first).
  let secretCapSent = $state(false);
  $effect(() => {
    if (secretCapSent || approving || previewPending || !onExpiryChange || ownerChoseExpiry || onceDefaultMs !== null) return;
    if (secretCapMs !== null && expiryMs === null && requestedExpiry !== null && cappedAskMs(requestedExpiry, secretCapMs) !== requestedExpiry) {
      secretCapSent = true;
      onExpiryChange(cappedAskMs(requestedExpiry, secretCapMs));
    }
  });
  function chooseExpiry(ms: number | null) {
    ownerChoseExpiry = true;
    onExpiryChange?.(ms);
  }
  // The one-time choice: 1 hour, or what the app asked for. The longer option goes no higher than what the server
  // allows this surface: a popup or frame limits every one-time pick to 7 days, a link or device follows the secret
  // cap, and a signed request follows the start it was capped to (its `askedMs` is the app's own ask).
  const onceCapMs = $derived(secretCapMs ?? (oncePickCapped ? SECRET_GRANT_MAX_SECONDS * 1000 : null));
  const onceChoice = $derived.by(() => {
    if (!onceExpiryDefault || !onExpiryChange || model.protocol !== "tinycloud-siwe-recap" || !onceTier) return null;
    const reach = onceReachOf(onceGrants);
    if (reach === null) return null;
    const asked = shortenOnlyExpiry ? shortenOnlyExpiry.askedMs : requestedExpiry;
    const cap = shortenOnlyExpiry
      ? (shortenOnlyExpiry.startMs < shortenOnlyExpiry.askedMs ? shortenOnlyExpiry.startMs : null)
      : onceCapMs;
    return { longer: onceLongerChoice(asked, cap), caution: onceCautionLine(reach) };
  });
  // A signed request for a secret's own key says where it starts and the most it can be.
  const signedLengthNote = $derived(
    shortenOnlyExpiry && !onceTier && renewal?.leaseMs == null && expiryFoldMaxMs !== null &&
    model.permissions.some(grantDecryptsOneSecret)
      ? shortenOnlyExpiry.lengthNote(shortenOnlyExpiry.startMs, expiryFoldMaxMs)
      : null,
  );

  // App keys: the standing-access line follows the decrypt statements, and a
  // `key.delete` action is listed even though it is never selected.
  const identity = $derived(appKeyIdentity(model));
  const originHost = $derived.by(() => {
    const origin = model.requester.verifiedOrigin;
    if (!origin) return null;
    try {
      return new URL(origin).host;
    } catch {
      return origin;
    }
  });
  // Names that come from a manifest are app-supplied text: they are shown only
  // after the display rules (`appDisplayName`), everywhere on this view.
  const requesterName = $derived(appDisplayName(model.requester.displayName) ?? originHost ?? "");
  const requesterUnverified = $derived(!requesterName && unverifiedRequester !== null);
  const requesterShown = $derived(requesterUnverified ? unverifiedRequester!.name : requesterName);
  const manifestNameShown = $derived(appDisplayName(model.requester.manifestName));
  const requestedBy = $derived(originHost ?? requesterName);
  const renewalOnlyLine = $derived.by(() => {
    const app = requesterShown || RENEWAL_ONLY_COPY.appFallback;
    if (!renewal) return previewPending ? null : RENEWAL_ONLY_COPY.unavailable(app);
    if (renewal.turnedOff) return RENEWAL_ONLY_COPY.turnedOff(app);
    return RENEWAL_ONLY_COPY.dependsOnRenewal(app);
  });
  // The sign-in heading is set in the largest text, so it names only what the request cannot write: a manifest name
  // OpenKey verified, else the verified origin host, else a name the surface took from OpenKey's own list. A recap
  // that hosts a new space on a node sets up hosting for the owner, so it keeps the protocol heading.
  const hostsSpace = $derived(readSpaceHostFacts(model) !== null);
  const verifiedAppName = $derived(
    model.requester.manifestNameProvenance === "verified" ? appDisplayName(model.requester.manifestName) : null,
  );
  const headingApp = $derived(hostsSpace ? null : (verifiedAppName ?? originHost ?? signInApp));
  const headline = $derived(oneSecretShown ? oneSecret!.headline : protocolHeadline(model.protocol, headingApp));
  // The id on a matched manifest comes from that manifest; an id the app sent beside a matched manifest that names
  // none is the app's own word, which the manifest neither confirms nor contradicts.
  const manifestMatched = $derived(model.metadataTrust.status === "origin-bound" || model.metadataTrust.status === "verified");
  // Beside the renewal box a fixed end date is wrong (ticked) or repeats the box (unticked), so it is not shown there.
  const appKeyAccessLine = $derived(
    !renewal && selectedGrants.some(grantIsAppKeyDecrypt) ? appKeyAccessStatement(model.expiry, formatLocalAccessEnd) : null,
  );
  const notGrantableStatements = $derived.by(() => {
    const rows = model.permissions.flatMap(appKeyNotGrantableStatements);
    return rows.filter((row, index) => rows.findIndex((other) => other.primaryText === row.primaryText) === index);
  });

  function isSelected(grant: CapabilityGrant, action: CapabilityAction): boolean {
    return (!grant.renewalOnly || renewalOn) && selection.has(action.id);
  }

  // The app keys of a request are approved with the rest of it or removed as
  // a unit: the server refuses a selection that keeps an app-key action and
  // drops any other action, so no control changes one without the other.
  const appKeyGrants = $derived(model.permissions.filter((grant) => grant.family === "app-keys"));
  const appKeyActionIds = $derived(
    new Set(appKeyGrants.flatMap((grant) => grant.actions.filter((action) => action.editable).map((action) => action.id))),
  );
  const firstAppKeyGrantId = $derived(appKeyGrants[0]?.id ?? null);

  const appKeysSelected = $derived([...appKeyActionIds].some((id) => selection.has(id)));

  function isLockedByAppKeys(action: CapabilityAction): boolean {
    return appKeysSelected && !appKeyActionIds.has(action.id);
  }

  function toggleAppKeys() {
    const next = new Set(selection);
    if (appKeysSelected) {
      for (const id of appKeyActionIds) next.delete(id);
    } else {
      for (const grant of model.permissions) {
        for (const action of grant.actions) {
          if (action.editable) next.add(action.id);
        }
      }
    }
    onSelectionChange(next);
  }

  function handleAppKeysKeydown(event: KeyboardEvent) {
    if (event.key === " " || event.key === "Enter") {
      event.preventDefault();
      toggleAppKeys();
    }
  }

  function toggle(action: CapabilityAction) {
    if (!action.editable) return;
    if (appKeyActionIds.has(action.id)) {
      toggleAppKeys();
      return;
    }
    if (isLockedByAppKeys(action)) return;
    const next = new Set(selection);
    if (next.has(action.id)) next.delete(action.id);
    else next.add(action.id);
    onSelectionChange(next);
  }

  function resetSelection() {
    const next = new Set<string>();
    for (const grant of model.permissions) {
      for (const action of grant.actions) {
        if (action.selected) next.add(action.id);
      }
    }
    onSelectionChange(next);
  }

  const SERVICE_LABELS: Record<string, string> = {
    "tinycloud.kv": "Key Value",
    kv: "Key Value",
    "tinycloud.sql": "SQL",
    sql: "SQL",
    "tinycloud.capabilities": "Permissions",
    capabilities: "Permissions",
    "tinycloud.delegation": "Delegation",
    delegation: "Delegation",
    "tinycloud.encryption": "Encryption",
    encryption: "Encryption",
    "tinycloud.secrets": "Secrets",
    secrets: "Secrets",
  };

  function compactService(service: string): string {
    return SERVICE_LABELS[service] ?? service;
  }

  function exactGrantTarget(grant: CapabilityGrant): string {
    const resourceService = grant.resourceService
      ? `/${grant.resourceService}`
      : "";
    const path = grant.path ? `/${grant.path}` : "";
    return `${grant.space}${resourceService}${path}`;
  }

  function compactSpace(space: string): string {
    const pkhSpace = space.match(
      /^tinycloud:pkh:eip155:\d+:0x[a-fA-F0-9]{40}:(.+)$/,
    );
    if (pkhSpace?.[1]) return pkhSpace[1];

    const encryptionSpace = space.match(
      /^urn:tinycloud:encryption:did:pkh:eip155:\d+:0x[a-fA-F0-9]{40}:(.+)$/,
    );
    return encryptionSpace?.[1] ?? space;
  }

  function compactGrantTarget(grant: CapabilityGrant): string {
    const space = compactSpace(grant.space);
    if (!grant.path) return space;
    return grant.path.startsWith("/")
      ? `${space}${grant.path}`
      : `${space}/${grant.path}`;
  }

  function handleKeydown(event: KeyboardEvent, action: CapabilityAction) {
    if (!action.editable) return;
    if (event.key === " " || event.key === "Enter") {
      event.preventDefault();
      toggle(action);
    }
  }

  // Honest trust labels. Each status maps to a phrase that describes ONLY
  // what the widget can prove — never overstates verification.
  const trustLabel: Record<
    CapabilityReviewModel["metadataTrust"]["status"],
    string
  > = {
    verified: "Manifest signature verified",
    "origin-bound": "Manifest served by verified https origin",
    unsigned: "No signed manifest",
    stale: "Manifest signature is stale",
    "wrong-key": "Manifest signed by an unknown key",
    "digest-mismatch": "Manifest digest does not match declared content",
  };

  // Copy-to-clipboard for the raw message. Uses the Async Clipboard API
  // and falls back to a hidden textarea + execCommand for older browsers.
  // The clipboard receives `model.rawMessage` EXACTLY — no normalization.
  let copyState = $state<"idle" | "copied" | "failed">("idle");

  function clipboardPolicyAllowsWrite(): boolean {
    if (typeof document === "undefined") return false;
    const policyDocument = document as Document & {
      permissionsPolicy?: { allowsFeature: (feature: string) => boolean };
      featurePolicy?: { allowsFeature: (feature: string) => boolean };
    };
    const policy =
      policyDocument.permissionsPolicy ?? policyDocument.featurePolicy;
    return policy?.allowsFeature
      ? policy.allowsFeature("clipboard-write")
      : true;
  }

  function copyWithExecCommand(text: string): boolean {
    if (typeof document === "undefined") return false;
    const activeElement =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.setAttribute("aria-hidden", "true");
    ta.style.position = "fixed";
    ta.style.inset = "0 auto auto -9999px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, text.length);
    const copied = document.execCommand("copy");
    ta.remove();
    activeElement?.focus();
    return copied;
  }

  async function writeClipboard(text: string): Promise<boolean> {
    let copied = false;
    if (
      typeof navigator !== "undefined" &&
      navigator.clipboard?.writeText &&
      clipboardPolicyAllowsWrite()
    ) {
      try {
        await navigator.clipboard.writeText(text);
        copied = true;
      } catch {
        // An iframe may expose Clipboard API while blocking it via
        // Permissions Policy. Fall through to the user-gesture fallback.
      }
    }
    if (!copied) {
      try {
        copied = copyWithExecCommand(text);
      } catch {
        copied = false;
      }
    }
    return copied;
  }

  async function copyRawMessage() {
    const copied = await writeClipboard(model.rawMessage);
    copyState = copied ? "copied" : "failed";
    setTimeout(() => {
      copyState = "idle";
    }, 2000);
  }

  // Space and node rows on a host approval. Derived from the bytes that are
  // signed (`model.rawMessage`), for the grants currently selected.
  const COPY_SPACE_ID = "Copy space ID";
  const COPY_NODE_ID = "Copy node ID";
  const COPIED = "Copied";
  const NODE_CHECKING = "Checking the node…";
  const NODE_NOT_CONFIRMED = "Not confirmed as a known TinyCloud node";
  const NODE_NOT_CONFIRMED_NOTE = "Approving lets this node store and serve your new space.";

  const hostFacts = $derived(readSpaceHostFacts(model, selection));
  let copiedValue = $state<string | null>(null);

  async function copyValue(value: string) {
    if (!(await writeClipboard(value))) return;
    copiedValue = value;
    setTimeout(() => {
      if (copiedValue === value) copiedValue = null;
    }, 2000);
  }

  // Approve is armed only when its button is enabled (settled layout, node checked, nothing blocking). A browser
  // already ignores a click on a disabled button; this also refuses one that reaches the handler anyway, such as after
  // a script clears the `disabled` attribute.
  function handleApproveClick() {
    if (approveButtonDisabled) return;
    // An extra permission (TC-2927) is approved only after its own decision: the screen opens first.
    if (elevated && pendingElevatedGroups.length > 0) {
      warningOpen = true;
      return;
    }
    onApprove();
  }

  // --- The warning screen for extra permissions (TC-2927) ---------------------------------------------------------
  interface ElevatedGroup {
    id: string;
    kind: ElevatedKind;
    actionIds: string[];
    decrypt: boolean;
    create: boolean;
    block: boolean;
    unblock: boolean;
    where: string | null;
    /** The all-secrets card: decrypt on a whole network, decrypt or key creation on `secrets/`. */
    allSecrets: boolean;
  }
  // What the request reaches across all secrets: the all-secrets card on the warning screen, or above the summary on
  // a screen without one (a link, the command line).
  const allSecrets = $derived(allSecretsReach(selectedGrants));
  // One group per selected grant that carries decrypt, key creation, or blocking or unblocking of keys on the
  // encryption network, or on keys outside the app's own `apps/` area. The same `elevatedKindOf` decides on the
  // server, so both see the same permissions. Every action that can open all secrets goes on one card of its own,
  // first, whichever grant carries it.
  const elevatedGroups = $derived.by((): ElevatedGroup[] => {
    if (!elevated) return [];
    const allSecretsActionIds: string[] = [];
    const groups = selectedGrants.flatMap((grant): ElevatedGroup[] => {
      const entry = { service: grant.service, space: grant.space, path: grant.path };
      const picked = grant.actions.flatMap((action) => {
        const kind = elevatedKindOf(entry, action.ability);
        if (kind === null) return [];
        if (allSecrets !== null && allSecretsAbility(entry, action.ability) !== null) {
          allSecretsActionIds.push(action.id);
          return [];
        }
        return [{ action, kind }];
      });
      if (picked.length === 0) return [];
      const has = (verb: string) => picked.some(({ action }) => elevatedAbilityVerb(action.ability) === verb);
      return [
        {
          id: grant.id,
          kind: picked[0]!.kind,
          actionIds: picked.map(({ action }) => action.id),
          decrypt: has("decrypt"),
          create: has("key.create"),
          block: has("key.block"),
          unblock: has("key.unblock"),
          where: elevatedWhere(entry),
          allSecrets: false,
        },
      ];
    });
    if (allSecretsActionIds.length === 0) return groups;
    return [
      {
        id: "all-secrets",
        kind: "encryption-network",
        actionIds: allSecretsActionIds,
        decrypt: true,
        create: false,
        block: false,
        unblock: false,
        where: null,
        allSecrets: true,
      },
      ...groups,
    ];
  });
  let allowedElevated = $state<Set<string>>(new Set());
  let rejectedCards = $state<Array<{ heading: string; actionIds: string[] }>>([]);
  let warningOpen = $state(false);
  let awaitingApprove = $state(false);
  const pendingElevatedGroups = $derived(
    elevatedGroups.filter((group) => !group.actionIds.every((id) => allowedElevated.has(id))),
  );
  // The site named on the cards: the browser-verified origin (for an embedded sign-in, the page that embeds it),
  // never a name the app supplies; "This request" where nothing is verified.
  const elevatedSite = $derived(originHost ?? null);
  const elevatedCards = $derived(
    pendingElevatedGroups.map((group) => {
      if (group.allSecrets && allSecrets !== null) {
        const card = allSecretsCard(allSecrets, elevatedSite);
        return { id: group.id, heading: card.heading, body: card.cue === null ? card.body : `${card.body} ${card.cue}` };
      }
      return {
        id: group.id,
        ...elevatedCard(
          group.kind,
          { decrypt: group.decrypt, create: group.create, block: group.block, unblock: group.unblock },
          elevatedSite,
          elevatedWhereText(group.where),
        ),
      };
    }),
  );
  // The master-key card's hint names the length the approval is signed for after the owner rejects it, or it does not
  // show. It shows only when the page can prove that length: a request this screen sends the app's own time for (no
  // owner pick, no renewal, only the one-hour start or nothing chosen), counted from now to the Expiration Time that is
  // signed, held to the cap the server takes from the original request (`secretCapMs` reads every grant, ticked or not).
  // It stays out where the length depends on more than the card: the app asked for an hour or less, the request without
  // the card is still in the one-hour tier, nothing else is left to approve, or several cards stand for the master key.
  const masterKeyLasts = $derived.by((): string | null => {
    if (shortenOnlyExpiry !== null || ownerChoseExpiry || renewal?.leaseMs != null) return null;
    if (expiryMs !== null && expiryMs !== ONCE_DEFAULT_EXPIRY_MS) return null;
    const asked = signedAsWrittenMs;
    if (asked === null || asked <= ONCE_DEFAULT_EXPIRY_MS || !isOnceTier(selectedGrants)) return null;
    const headings = new Map(elevatedCards.map((card) => [card.id, card.heading]));
    const masterGroups = pendingElevatedGroups.filter((group) => headings.get(group.id) === MASTER_KEY_TITLE);
    if (masterGroups.length !== 1) return null;
    const masterIds = new Set(masterGroups[0]!.actionIds);
    const elevatedIds = new Set(pendingElevatedGroups.flatMap((group) => group.actionIds));
    const left = (drop: Set<string>) =>
      selectedGrants
        .map((grant) => ({ ...grant, actions: grant.actions.filter((action) => !drop.has(action.id)) }))
        .filter((grant) => grant.actions.length > 0);
    if (left(elevatedIds).length === 0) return null;
    const without = left(masterIds);
    if (isOnceTier(without)) return null;
    const ms = cappedAskMs(asked, secretCapMs);
    return ms <= ONCE_DEFAULT_EXPIRY_MS ? null : formatDurationWithEnd(ms);
  });
  const elevatedCardsShown = $derived(
    elevatedCards.map((card) => ({
      ...card,
      rejectNote: card.heading === MASTER_KEY_TITLE && masterKeyLasts !== null ? masterKeyRejectNote(elevatedSite, masterKeyLasts) : null,
    })),
  );
  const allSecretsSummaryCard = $derived(!elevated && allSecrets !== null ? allSecretsCard(allSecrets, originHost ?? null) : null);
  const notApprovedRows = $derived(
    rejectedCards.filter((card) => card.actionIds.every((id) => !selection.has(id))).map((card) => elevatedNotApprovedRow(card.heading)),
  );

  async function resolveElevated(allowedCardIds: string[]) {
    const allowedGroups = pendingElevatedGroups.filter((group) => allowedCardIds.includes(group.id));
    const rejectedGroups = pendingElevatedGroups.filter((group) => !allowedCardIds.includes(group.id));
    const nextAllowed = new Set(allowedElevated);
    for (const group of allowedGroups) for (const id of group.actionIds) nextAllowed.add(id);
    allowedElevated = nextAllowed;
    if (rejectedGroups.length > 0) {
      const headings = new Map(elevatedCards.map((card) => [card.id, card.heading]));
      rejectedCards = [
        ...rejectedCards,
        ...rejectedGroups.map((group) => ({ heading: headings.get(group.id) ?? "", actionIds: group.actionIds })),
      ];
      const next = new Set(selection);
      for (const group of rejectedGroups) for (const id of group.actionIds) next.delete(id);
      onSelectionChange(next);
    }
    // The allowed ids go into the next preview (or the exact-byte sign); Approve then continues on its own, once that
    // preview is ready, so the owner's one tap on Approve is still the only approval.
    elevated?.onDecide([...nextAllowed]);
    warningOpen = false;
    await tick();
    awaitingApprove = true;
    document.getElementById("signing-approval-headline")?.focus();
  }

  async function allowWholeElevated() {
    const nextAllowed = new Set(allowedElevated);
    for (const group of pendingElevatedGroups) for (const id of group.actionIds) nextAllowed.add(id);
    allowedElevated = nextAllowed;
    elevated?.onDecide([...nextAllowed]);
    warningOpen = false;
    await tick();
    awaitingApprove = true;
  }

  $effect(() => {
    if (!awaitingApprove || warningOpen || previewPending || approving || approveButtonDisabled) return;
    awaitingApprove = false;
    handleApproveClick();
  });

  const nodeChecking = $derived(peerRecognition?.state === "checking");
  const approveDisabled = $derived(approving || isMalformedRecap);
  const approveButtonDisabled = $derived(
    previewPending || onceDefaultPending || layoutBlocked || refused || approveDisabled || Boolean(approveBlockedReason) || approveBlockedByFailure || nodeChecking || declining,
  );

  // A page that offers the one-passkey cover watches its Approve button: the cover counts only while the button is in
  // plain view, and the 500 ms restarts each time Approve becomes actionable.
  let approveButton = $state<HTMLButtonElement | null>(null);
  $effect(() => {
    const visibility = approveVisibility;
    if (!visibility) return;
    visibility.watch(approveButton);
    return () => visibility.watch(null);
  });
  $effect(() => {
    if (!approveButtonDisabled) approveVisibility?.restart();
  });
  const approveLabel = $derived(
    isMalformedRecap
      ? "Cannot approve"
      : approving
        ? "Signing…"
        : previewPending && !onRetry && !refused
          ? "Getting ready…"
          : approveText,
  );
</script>

{#if warningOpen && elevated}
  <ElevatedWarning
    cards={elevatedCardsShown}
    site={elevatedSite}
    splittable={elevated.splittable}
    onResolve={resolveElevated}
    onAllowWhole={allowWholeElevated}
    onCancel={onCancel}
  />
{:else}
<div
  class="signing-approval"
  class:sticky-actions={stickyActions}
  role="dialog"
  aria-modal="true"
  aria-labelledby="signing-approval-headline"
  aria-describedby="signing-approval-hint"
  tabindex="-1"
>
  <header class="header">
    {#if identity}
      <!-- The app's name, then its id; the name never appears without the id. -->
      {#if identity.name}
        <h2 id="signing-approval-headline" class="headline app-name" tabindex="-1">{identity.name}</h2>
        <p class="app-id mono">{identity.appId}</p>
      {:else}
        <h2 id="signing-approval-headline" class="headline app-id-headline mono" tabindex="-1">{identity.appId}</h2>
      {/if}
      <p class="requester-line">
        Requested by <span class="requester-name">{requestedBy}</span>
      </p>
    {:else}
      <h2 id="signing-approval-headline" class="headline" tabindex="-1">{headline}</h2>
      <p class="requester-line">
        Requested by <span class="requester-name">{requesterShown}</span>
      </p>
      {#if requesterUnverified}
        <p class="requester-line">{unverifiedRequester!.line}</p>
      {/if}
    {/if}
    <p id="signing-approval-hint" class="hint">{hint}</p>
  </header>

  <!-- The app's own words about a plain sign request, under the verified origin and marked as unchecked. -->
  {#if claimed}
    <ClaimedPresentation view={claimed} />
  {/if}

  {#if context}
    <div class="context">{@render context()}</div>
  {/if}

  <!-- Reason only when a reason actually exists. -->
  {#if model.reason.source !== "none" && model.reason.text}
    <section class="reason" aria-label="Reason for request">
      <div class="reason-label">Reason provided by {model.reason.source === "caller" ? "the requester" : requesterName}</div>
      <p class="reason-body">{model.reason.text}</p>
      {#if model.reason.source === "caller"}
        <p class="reason-untrusted">
          This reason comes from the caller and is not verified.
        </p>
      {/if}
    </section>
  {/if}

  {#if showSigner}
    <p class="signer-line" aria-label="Signing key">
      <span class="signer-line-label">Signing with</span>
      <span class="signer-line-name">{model.signer.label}</span>
      <code class="mono" title={model.signer.address}>{shortSignerAddress}</code>
    </p>
  {/if}

  <!--
    Count the badged rows only when mixed with unbadged rows. Not-granted
    informational rows are also unbadged; the individual badges always remain.
  -->
  {#if sensitiveCount > 0 && sensitiveCount < effectiveStatements.length + notGrantableStatements.length}
    <p class="sensitive-callout" role="status" aria-live="polite">
      {sensitiveRowsCallout(sensitiveCount)}
    </p>
  {/if}

  {#snippet statementText(text: string, codeSpans: boolean)}
    {#if codeSpans}
      {#each splitStatementCode(text) as part}{#if part.code}<code class="mono">{part.text}</code>{:else}{part.text}{/if}{/each}
    {:else}
      {text}
    {/if}
  {/snippet}

  <!--
    Default summary: short list of deterministic statements.
    Never invents friendly semantics for unknown shapes (see statements.ts).
    Requester provenance and exact resource identifiers are deliberately kept
    in Advanced details so the first viewport is useful to ordinary users.
  -->
  {#snippet summaryRow(statement: SummaryStatement, active = true)}
    <li class="summary-statement" data-severity={active ? statement.severity : undefined}>
      <span class="statement-line">
        <span class="statement-primary">{@render statementText(statement.primaryText, statement.codeSpans)}</span>
        {#if active && statement.severity === "sensitive"}
          <span class="summary-sensitive-pill">Sensitive</span>
        {/if}
      </span>
      {#if oneSecretShown && statement.key === NAMED_SECRET_DECRYPT_ROW}
        <span class="statement-detail">{oneSecret!.decryptNote}</span>
      {:else if statement.detail}
        <span class="statement-detail">{statement.detail}</span>
      {/if}
    </li>
  {/snippet}

  <section class="summary" aria-label="Requested access">
    {#if identity && effectiveStatements.length > 0}
      <p class="summary-lead">{appRequestingLine(identity.name)}</p>
    {/if}
    {#if allSecretsSummaryCard}
      <div class="all-secrets" role="note" aria-labelledby="all-secrets-heading" data-testid="all-secrets-card">
        <h3 class="all-secrets-heading" id="all-secrets-heading">{allSecretsSummaryCard.heading}</h3>
        <p class="all-secrets-body">{allSecretsSummaryCard.body}</p>
        {#if allSecretsSummaryCard.cue}
          <p class="all-secrets-body">{allSecretsSummaryCard.cue}</p>
        {/if}
      </div>
    {/if}
    {#if summaryStatements.length > 0}
      <ul class="summary-statements">
        {#each summaryStatements as statement (statement.key)}
          {#if groupSecrets && statement.secret !== undefined}
            {#if statement === secretStatements[0]}
              <li class="summary-statement" data-severity="sensitive">
                <details class="secret-summary">
                  <summary>
                    <span class="statement-line">
                      <span class="statement-primary">Read {secretStatements.length} secrets</span>
                      <span class="summary-sensitive-pill">Sensitive</span>
                    </span>
                    <span class="link show-secrets">Show the secrets</span>
                    <span class="link hide-secrets">Hide the secrets</span>
                  </summary>
                  <ul class="secret-statements">
                    {#each secretStatements as row (row.key)}
                      <li><code class="mono">{row.secret!.name}</code></li>
                    {/each}
                  </ul>
                </details>
              </li>
            {/if}
          {:else}
            {@render summaryRow(statement)}
          {/if}
        {/each}
      </ul>
    {:else if !isMalformedRecap && effectiveStatements.length === 0}
      <p class="summary-empty">
        {model.permissions.length > 0
          ? "No optional access selected."
          : "No capability payload — exact-byte signature only."}
      </p>
    {/if}
    {#if renewalOnlyStatements.length > 0}
      <section aria-label={RENEWAL_ONLY_COPY.heading}>
        <h3 class="all-secrets-heading">{RENEWAL_ONLY_COPY.heading}</h3>
        {#if renewalOnlyLine}
          <p class="summary-note">{renewalOnlyLine}</p>
        {/if}
        <ul class="summary-statements">
          {#each renewalOnlyStatements as statement (statement.key)}
            {@render summaryRow(statement, renewalOn)}
          {/each}
        </ul>
      </section>
    {/if}
    {#if appKeyAccessLine}
      <p class="summary-note">{appKeyAccessLine}</p>
    {/if}
    {#if notGrantableStatements.length > 0}
      <ul class="summary-statements summary-not-granted">
        {#each notGrantableStatements as statement (statement.primaryText)}
          <li class="summary-statement" data-severity="sensitive">
            <span class="statement-line">
              <span class="statement-primary">{@render statementText(statement.primaryText, statement.codeSpans === true)}</span>
            </span>
          </li>
        {/each}
      </ul>
    {/if}

    {#if onExpiryChange && model.protocol === "tinycloud-siwe-recap" && !onceDefaultPending}
      <ApprovalExpiryControl
        requestedMs={requestedExpiry}
        chosenMs={expiryMs}
        maxMs={unsignedMaxMs}
        disabled={approving}
        onChange={chooseExpiry}
        {onceChoice}
        lengthNote={signedLengthNote}
        {renewal}
        sensitive={renewalSensitive}
        {requestedBy}
        chooser={false}
        permissionCount={effectiveStatements.length}
      />
    {:else if !onExpiryChange && signedAsWrittenMs !== null}
      <p class="summary-note" data-testid="approval-access-line">{accessLastsLine("app", signedAsWrittenMs)}</p>
    {/if}

    {#if hostFacts}
      <dl class="host-facts">
        {#each hostFacts.spaces as space (space.spaceId)}
          <div class="host-fact">
            <dt class="host-fact-label">Space</dt>
            <dd class="host-fact-value">
              {#if space.spaceName}
                <span class="host-fact-name">{space.spaceName}</span>
              {/if}
              <code class="mono" title={space.spaceId}>{space.spaceName ? abbreviateSpaceId(space.spaceId) : space.spaceId}</code>
              <button
                type="button"
                class="copy-btn"
                aria-label={copiedValue === space.spaceId ? COPIED : COPY_SPACE_ID}
                title={copiedValue === space.spaceId ? COPIED : COPY_SPACE_ID}
                onclick={() => copyValue(space.spaceId)}
              >
                {copiedValue === space.spaceId ? COPIED : COPY_SPACE_ID}
              </button>
            </dd>
          </div>
        {/each}
        {#if hostFacts.peerDid && peerRecognition}
          <div class="host-fact">
            <dt class="host-fact-label">Node ID</dt>
            <dd class="host-fact-value">
              <code class="mono" title={hostFacts.peerDid}>{abbreviateDid(hostFacts.peerDid)}</code>
              <button
                type="button"
                class="copy-btn"
                aria-label={copiedValue === hostFacts.peerDid ? COPIED : COPY_NODE_ID}
                title={copiedValue === hostFacts.peerDid ? COPIED : COPY_NODE_ID}
                onclick={() => copyValue(hostFacts.peerDid ?? "")}
              >
                {copiedValue === hostFacts.peerDid ? COPIED : COPY_NODE_ID}
              </button>
            </dd>
          </div>
        {/if}
      </dl>
      {#if hostFacts.peerDid && peerRecognition}
        <div class="host-node-status" id="host-node-status" role="status" aria-live="polite" data-node-state={peerRecognition.state}>
          {#if peerRecognition.state === "checking"}
            <p class="host-marker">{NODE_CHECKING}</p>
          {:else if peerRecognition.state === "known"}
            <p class="host-marker">Known TinyCloud node at <span class="mono">{peerRecognition.origin}</span></p>
          {:else}
            <p class="host-marker">{NODE_NOT_CONFIRMED}</p>
            <p class="host-marker-note">{NODE_NOT_CONFIRMED_NOTE}</p>
          {/if}
        </div>
      {/if}
    {/if}
  </section>

  <!--
    Single Advanced details disclosure. Contains: requester, verified
    origin, manifest name/appId/digest + honest trust label, reason (when
    present), signing identity, categorized exact-grant list with
    Edit/Reset controls, full raw message + Copy text.
  -->
  <details class="advanced-details">
    <summary class="advanced-summary">Advanced details</summary>

    <details class="request-details" open>
      <summary class="request-details-summary">Requester and signing details</summary>

      <section class="identity" aria-label="Requester identity">
      <div class="row">
        <span class="label">Requester</span>
        <span class="value">{requesterShown}</span>
      </div>

      {#if model.requester.verifiedOrigin}
        <div class="row">
          <span class="label">Verified browser origin</span>
          <code class="value mono">{model.requester.verifiedOrigin}</code>
        </div>
      {/if}

      <!--
        `originWarning` and `domainWarning` render INDEPENDENTLY. A
        concrete verified origin that disagrees with the SIWE domain must
        show BOTH warnings — never mask domainWarning behind originWarning.
      -->
      {#if model.requester.originWarning}
        <div class="row">
          <span class="warn" role="status">
            Origin warning: parent frame could not be attributed to a specific origin
          </span>
        </div>
      {/if}
      {#if model.requester.domainWarning}
        <div class="row">
          <span class="warn" role="status">
            Domain warning: SIWE domain does not match the verified browser origin
          </span>
        </div>
      {/if}

      <!--
        Sol MAJOR-4: render `manifestName` as a distinct field with its
        provenance stamp. `origin-bound` fields come from a well-known
        manifest whose digest matched the caller-supplied envelope;
        `caller` fields are unverified envelope echoes and MUST carry a
        visible "unverified" hint so an operator cannot mistake them for
        a trusted label. Server code never marks a caller-echoed name as
        origin-bound — see the popup/embed prepare handlers.
      -->
      {#if manifestNameShown}
        <div class="row">
          <span class="label">Manifest name</span>
          <span class="value">{manifestNameShown}</span>
          <span
            class="provenance-tag"
            data-provenance={model.requester.manifestNameProvenance}
          >
            {#if model.requester.manifestNameProvenance === "verified"}
              signed manifest
            {:else if model.requester.manifestNameProvenance === "origin-bound"}
              from origin-bound manifest
            {:else if model.requester.manifestNameProvenance === "caller"}
              caller-supplied, unverified
            {/if}
          </span>
        </div>
      {/if}

      <!--
        Sol minor: render `appId` and `manifestId` as SEPARATE Advanced-
        details rows. `appId` names the app (from the manifest's
        `app_id`); `manifestId` is the versioned identifier of the
        manifest itself. They agree only when a manifest is unversioned
        and both fields have been set to the same string; anywhere
        else, showing only `manifestId` would hide "which app is this?"
        from the operator.
      -->
      {#if model.requester.appId}
        <div class="row">
          <span class="label">App ID</span>
          <code class="value mono">{model.requester.appId}</code>
        </div>
      {/if}
      {#if model.requester.manifestId}
        <div class="row">
          <span class="label">Manifest ID</span>
          <code class="value mono">{model.requester.manifestId}</code>
          <span
            class="provenance-tag"
            data-provenance={model.requester.manifestIdProvenance}
          >
            {#if model.requester.manifestIdProvenance === "verified"}
              signed manifest
            {:else if model.requester.manifestIdProvenance === "origin-bound"}
              from origin-bound manifest
            {:else if model.requester.manifestIdProvenance === "caller"}
              {#if manifestMatched}
                from the app's request, unverified; the manifest doesn't name one
              {:else}
                caller-supplied, unverified
              {/if}
            {/if}
          </span>
        </div>
      {/if}
      {#if model.requester.manifestDigest}
        <div class="row">
          <span class="label">Manifest digest</span>
          <code class="value mono">{model.requester.manifestDigest}</code>
        </div>
      {/if}
      <div class="row">
        <span class="label">Manifest trust</span>
        <span
          class="value trust-value"
          data-trust={model.metadataTrust.status}
        >
          {trustLabel[model.metadataTrust.status]}
        </span>
      </div>
      {#if model.metadataTrust.reason}
        <p class="metadata-reason">{model.metadataTrust.reason}</p>
      {/if}
      </section>

      <section class="signer" aria-label="Signing identity">
        <div class="row">
          <span class="label">Signing with</span>
          <span class="value">{model.signer.label}</span>
          <code class="value mono">{model.signer.address}</code>
        </div>
        {#if model.expiry}
          <div class="row">
            <span class="label">Expires</span>
            <span class="value">{model.expiry}</span>
          </div>
        {:else if model.protocol === "siwe-plain" || model.protocol === "tinycloud-siwe-recap"}
          <div class="row" data-testid="siwe-no-expiry">
            <span class="label">Expires</span>
            <span class="value">{SIWE_WITHOUT_EXPIRY}</span>
          </div>
        {/if}
      </section>
    </details>

    {#if onExpiryChange && model.protocol === "tinycloud-siwe-recap" && !onceDefaultPending && (expiryMs ?? requestedExpiry) !== null}
      <details class="request-details expiry-fold">
        <summary class="request-details-summary">How long it lasts</summary>
        <ApprovalExpiryChooser
          requestedMs={shortenOnlyExpiry?.startMs ?? requestedExpiry}
          chosenMs={expiryMs}
          maxMs={expiryFoldMaxMs}
          limitNote={shortenOnlyExpiry?.limitNote}
          disabled={approving}
          explicitAsked={onceDefaultMs !== null}
          onChange={chooseExpiry}
          {renewal}
        />
      </details>
    {/if}

    {#if model.permissions.length > 0}
      <section class="permissions" aria-label="Exact grants">
        <div class="permissions-header">
          <h3 class="permissions-heading">Exact grants</h3>
          {#if isEditable}
            <div class="permissions-actions">
              <button
                type="button"
                class="link"
                onclick={() => onEditingChange(!editing)}
                aria-expanded={editing}
                disabled={approveDisabled}
              >
                {editing ? "Done editing" : "Edit"}
              </button>
              <button
                type="button"
                class="link"
                onclick={resetSelection}
                disabled={approveDisabled}
              >
                Reset
              </button>
            </div>
          {/if}
        </div>

        {#if editing && appKeyGrants.length > 0}
          <p class="app-key-note">{APP_KEY_GROUP_NOTE}</p>
        {/if}
        {#each permissionSections as bucket (bucket.key)}
          <details
            class="severity-bucket"
            data-severity={bucket.severity}
            aria-label={bucket.heading}
            open={bucket.defaultOpen}
          >
            <summary class="bucket-summary">
              <span class="bucket-heading">{bucket.heading}</span>
              <span class="bucket-hint">{bucket.hint}</span>
            </summary>
            <div class="bucket-content">
              <ul class="grant-list">
                {#each bucket.grants as grant}
                  {@const unselectedActions = grant.actions.filter(
                    (action) => !isSelected(grant, action),
                  )}
                  <li class="grant">
                    <div class="grant-heading">
                      <span class="grant-title">{grantHeading(grant)}</span>
                      {#if grant.severity === "sensitive"}
                        <span class="grant-severity" data-severity="sensitive">
                          Sensitive
                        </span>
                      {/if}
                    </div>
                    <code class="grant-path mono">
                      <span
                        class="grant-service"
                        title={grant.service}
                        aria-label={`Exact service: ${grant.service}`}
                      >{compactService(grant.service)}</span>
                      <span
                        class="grant-target"
                        title={exactGrantTarget(grant)}
                        aria-label={`Exact resource: ${exactGrantTarget(grant)}`}
                      >
                        {compactGrantTarget(grant)}
                      </span>
                    </code>
                    {#if grant.ownedBySelf === false}
                      <p class="cross-app-warning">
                        This data belongs to another user.
                      </p>
                    {/if}
                    {#if editing && grant.id === firstAppKeyGrantId}
                      <label class="action-toggle app-key-group">
                        <input
                          type="checkbox"
                          checked={appKeysSelected}
                          onchange={toggleAppKeys}
                          onkeydown={handleAppKeysKeydown}
                          disabled={approveDisabled}
                        />
                        <span class="verb">{FAMILY_LABEL["app-keys"]}</span>
                      </label>
                    {/if}
                    <ul class="action-list">
                      {#each editing ? grant.actions : grant.actions.filter((action) => isSelected(grant, action)) as action}
                        <li class="action">
                          {#if editing && action.editable && !appKeyActionIds.has(action.id)}
                            <label class="action-toggle">
                              <input
                                type="checkbox"
                                checked={isSelected(grant, action)}
                                onchange={() => toggle(action)}
                                onkeydown={(e) => handleKeydown(e, action)}
                                disabled={approveDisabled || isLockedByAppKeys(action) || (grant.renewalOnly && !renewalOn)}
                              />
                              <span class="verb">{action.verb}</span>
                            </label>
                          {:else}
                            <span class="action-static">
                              <span class="verb">{action.verb}</span>
                              {#if action.required}
                                <span class="required-flag">required</span>
                              {/if}
                            </span>
                          {/if}
                        </li>
                      {/each}
                    </ul>
                    {#if unselectedActions.length > 0}
                      <p class="not-granting">
                        <span>Not granting:</span>
                        {unselectedActions.map((action) => action.verb).join(", ")}
                      </p>
                    {/if}
                  </li>
                {/each}
              </ul>
            </div>
          </details>
        {/each}
      </section>
    {/if}

    {#if model.parseWarnings.length > 0}
      <section class="warnings" aria-label="Parser warnings">
        <h4 class="warnings-heading">Notes</h4>
        <ul>
          {#each model.parseWarnings as warning}
            <li class="warning">
              <code class="warning-code mono">{warning.code}</code>
              {warning.message}
            </li>
          {/each}
        </ul>
      </section>
    {/if}

    <section class="raw" aria-label="Raw message that will be signed">
      <div class="raw-header">
        <h4 class="raw-heading">Exact bytes being signed</h4>
        <button
          type="button"
          class="copy-btn"
          onclick={copyRawMessage}
          aria-label="Copy text"
        >
          {copyState === "copied"
            ? "Copied"
            : copyState === "failed"
              ? "Copy failed"
              : "Copy text"}
        </button>
      </div>
      <pre class="raw-bytes" aria-live="polite">{renderSiweLiteral(model.rawMessage)}</pre>
    </section>
  </details>

  <!-- The message and the buttons travel together: with sticky actions the message is pinned just above them, so a
       refusal is never left below the fold of a short frame while the buttons look unchanged. -->
  <div class="action-region">
  {#if error}
    <p class="error" role="alert" aria-live="polite">{error}</p>
    {#if errorDetail}
      <details class="error-detail">
        <summary>Details</summary>
        <p>{errorDetail}</p>
      </details>
    {/if}
  {/if}
  {#if approveBlockedReason && approveBlockedReason !== error}
    <p class="approve-blocked" role="status" aria-live="polite">{approveBlockedReason}</p>
  {/if}

  {#if onDecline}
    <!-- With Decline offered, going back is a quiet link above the Decline / Approve pair. -->
    <button
      type="button"
      class="dismiss-link"
      data-testid="signing-dismiss"
      onclick={onCancel}
      disabled={approving || declining}
    >
      {cancelText}
    </button>
  {/if}
  {#if notApprovedRows.length > 0}
    <ul class="not-approved" data-testid="elevated-not-approved">
      {#each notApprovedRows as row (row)}
        <li>{row}</li>
      {/each}
    </ul>
    <p class="visually-hidden" role="status" aria-live="polite">{elevatedRejectedCountAnnouncement(notApprovedRows.length)}</p>
  {/if}
  <footer class="actions">
    {#if onDecline}
      <button
        type="button"
        class="cancel decline"
        data-testid="signing-decline"
        onclick={onDecline}
        disabled={approving || declining}
      >
        {declineText}
      </button>
    {:else}
      <button
        type="button"
        class="cancel"
        data-testid="signing-dismiss"
        onclick={onCancel}
        disabled={approving}
      >
        {cancelText}
      </button>
    {/if}
    {#if onRetry}
      <button type="button" class="cancel" onclick={onRetry} disabled={approving}>Try again</button>
    {/if}
    <button
      type="button"
      class="approve"
      bind:this={approveButton}
      onclick={handleApproveClick}
      disabled={approveButtonDisabled}
      aria-disabled={approveButtonDisabled}
      aria-describedby={nodeChecking ? "host-node-status" : undefined}
    >
      {approveLabel}
    </button>
  </footer>
  </div>
</div>
{/if}

<style>
  .signing-approval {
    display: flex;
    flex-direction: column;
    gap: 14px;
    width: min(100%, 560px);
    max-width: 560px;
    margin: 0 auto;
    padding: 18px;
    box-sizing: border-box;
    background: #fff;
    border: 1px solid #dbe2ea;
    border-radius: 16px;
    color: #0f172a;
  }
  .header {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .headline {
    font-size: 20px;
    font-weight: 700;
    line-height: 1.2;
    margin: 0;
    text-wrap: balance;
  }
  .hint {
    font-size: 14px;
    line-height: 1.5;
    color: #475569;
    margin: 0;
  }
  .app-name,
  .app-id-headline {
    unicode-bidi: isolate;
    overflow-wrap: anywhere;
  }
  .app-id {
    font-size: 13px;
    line-height: 1.3;
    color: #475569;
    margin: 0;
    overflow-wrap: anywhere;
  }
  .app-id-headline {
    font-size: 17px;
  }
  .summary-lead {
    font-size: 14px;
    font-weight: 600;
    margin: 0 0 6px;
    unicode-bidi: isolate;
    overflow-wrap: anywhere;
  }
  /* The all-secrets card on a screen without the warning screen: the same colours as the Sensitive callout. */
  .all-secrets {
    background: #fff7ed;
    border: 1px solid #fdba74;
    border-radius: 12px;
    padding: 10px 12px;
    color: #9a3412;
  }
  .all-secrets-heading {
    margin: 0;
    font-size: 14px;
    line-height: 1.4;
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .all-secrets-body {
    margin: 4px 0 0;
    font-size: 13px;
    line-height: 1.45;
  }
  .requester-line {
    font-size: 13px;
    line-height: 1.45;
    color: #475569;
    margin: 0;
  }
  .requester-name {
    font-weight: 600;
    color: #0f172a;
  }
  .context {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .reason {
    padding: 10px 12px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
  }
  .reason-label {
    font-size: 12px;
    font-weight: 600;
    color: #475569;
  }
  .reason .reason-body {
    font-size: 13px;
    color: #0f172a;
    overflow-wrap: anywhere;
  }
  .signer-line {
    display: flex;
    align-items: baseline;
    gap: 8px;
    flex-wrap: wrap;
    margin: 0;
    font-size: 13px;
    line-height: 1.45;
  }
  .signer-line-label {
    color: #475569;
  }
  .signer-line-name {
    font-weight: 600;
  }
  .sensitive-callout {
    background: #fff7ed;
    color: #9a3412;
    border: 1px solid #fdba74;
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 13px;
    line-height: 1.45;
    margin: 0;
    font-weight: 600;
  }
  .summary {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 14px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
  }
  .summary-statements {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .summary-statement {
    padding: 7px 0;
    display: flex;
    flex-direction: column;
    border-bottom: 1px solid #e2e8f0;
  }
  .summary-statement:last-child {
    border-bottom: 0;
  }
  .summary-statement[data-severity="sensitive"] {
    color: #9f2424;
  }
  .summary-statement[data-severity="attention"] {
    color: #7c4a03;
  }
  .statement-primary {
    /* A long unbroken id (a 32-hex share key) wraps inside the row instead of pushing the Sensitive pill off the card. */
    min-width: 0;
    overflow-wrap: anywhere;
    font-size: 13px;
    line-height: 1.45;
    font-weight: 600;
    color: #0f172a;
  }
  .secret-summary > summary {
    cursor: pointer;
    list-style: none;
  }
  .secret-summary > summary::-webkit-details-marker {
    display: none;
  }
  .secret-summary:not([open]) .hide-secrets,
  .secret-summary[open] .show-secrets {
    display: none;
  }
  .secret-statements {
    margin: 6px 0 0;
    padding-inline-start: 18px;
  }
  .secret-statements > li + li {
    margin-top: 4px;
  }
  .statement-detail {
    margin-top: 2px;
    font-size: 12px;
    line-height: 1.45;
    color: #475569;
  }
  .statement-line {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
  }
  .summary-sensitive-pill {
    flex: 0 0 auto;
    border: 1px solid #f2c0c0;
    border-radius: 999px;
    background: #fff7f7;
    color: #9f2424;
    padding: 2px 7px;
    font-size: 10px;
    font-weight: 700;
    line-height: 1.3;
  }
  .not-approved {
    margin: 0;
    padding: 0 0 0 18px;
    font-size: 13px;
    line-height: 1.45;
    color: #9f2424;
    overflow-wrap: anywhere;
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    margin: -1px;
    padding: 0;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
  .summary-empty {
    color: #475569;
    font-size: 13px;
    line-height: 1.45;
    margin: 0;
  }
  .host-facts {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin: 0;
    padding-top: 8px;
    border-top: 1px solid #e2e8f0;
  }
  .host-fact {
    display: grid;
    grid-template-columns: 72px minmax(0, 1fr);
    gap: 4px 10px;
    align-items: start;
  }
  .host-fact-label {
    font-size: 12px;
    font-weight: 600;
    line-height: 1.6;
    color: #475569;
  }
  .host-fact-value {
    margin: 0;
    min-width: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 8px;
    overflow-wrap: anywhere;
  }
  .host-fact-name {
    font-size: 13px;
    font-weight: 700;
    color: #0f172a;
  }
  .host-node-status {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 10px;
    border: 1px solid #cbd5e1;
    border-radius: 10px;
    background: #fff;
    font-size: 13px;
    line-height: 1.45;
    color: #0f172a;
  }
  .host-node-status[data-node-state="known"] {
    border-color: #a7d7b8;
    background: #f3fbf6;
  }
  .host-node-status[data-node-state="other"] {
    border-color: #f1d28a;
    background: #fffaf0;
  }
  .host-marker {
    margin: 0;
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .host-marker-note {
    margin: 0;
    font-size: 12px;
    color: #475569;
  }
  .app-key-note {
    margin: 0 0 8px;
    color: #475569;
    font-size: 13px;
    line-height: 1.45;
  }
  .summary-note {
    color: #475569;
    font-size: 13px;
    line-height: 1.45;
    margin: 0;
  }
  .advanced-details {
    background: #fff;
    border: 1px solid #dbe2ea;
    border-radius: 14px;
    padding: 12px 14px;
    font-size: 13px;
    display: block;
  }
  .advanced-details[open] {
    display: flex;
    flex-direction: column;
    gap: 10px;
    background: #fbfdff;
    border-color: #cfd8e3;
  }
  .advanced-summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    cursor: pointer;
    font-weight: 700;
    color: #0f172a;
    padding: 2px 0;
    list-style: none;
  }
  .advanced-details[open] > .advanced-summary {
    padding-bottom: 6px;
  }
  .advanced-summary::-webkit-details-marker {
    display: none;
  }
  .advanced-summary::after {
    content: "▾";
    color: #64748b;
    transition: transform 160ms ease;
  }
  .advanced-details[open] .advanced-summary::after {
    transform: rotate(180deg);
  }
  .request-details {
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 10px;
  }
  .request-details-summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    cursor: pointer;
    list-style: none;
    color: #475569;
    font-size: 12px;
    font-weight: 600;
  }
  .request-details-summary::-webkit-details-marker {
    display: none;
  }
  .request-details-summary::after {
    content: "▾";
    color: #64748b;
    transition: transform 160ms ease;
  }
  .request-details[open] > .request-details-summary::after {
    transform: rotate(180deg);
  }
  .request-details[open] > .identity,
  .request-details[open] > .signer {
    margin-top: 10px;
  }
  .row {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    flex-wrap: wrap;
    font-size: 13px;
    line-height: 1.45;
    padding: 3px 0;
  }
  .label {
    color: #475569;
    font-weight: 600;
    min-width: 136px;
  }
  .value {
    color: #0f172a;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    color: #334155;
    word-break: break-word;
  }
  .trust-value {
    font-weight: 600;
  }
  .trust-value[data-trust="verified"] {
    color: #14733b;
  }
  .trust-value[data-trust="origin-bound"] {
    color: #4a6f2f;
  }
  .trust-value[data-trust="unsigned"] {
    color: #666;
  }
  .trust-value[data-trust="stale"],
  .trust-value[data-trust="wrong-key"],
  .trust-value[data-trust="digest-mismatch"] {
    color: #9f2424;
  }
  .warn {
    background: #fef3c7;
    color: #92400e;
    border: 1px solid #fde68a;
    padding: 3px 8px;
    border-radius: 999px;
    font-size: 12px;
    line-height: 1.35;
  }
  /*
    Sol MAJOR-4: provenance tags are attached to Advanced-details fields
    whose value came from a caller-echoed envelope. They exist so an
    operator can never mistake a `caller-supplied, unverified` string
    for an OpenKey-verified identity. The `caller` variant is styled
    like the domain warning; `origin-bound` and `verified` variants are
    neutral so they do not compete with content.
  */
  .provenance-tag {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 999px;
    line-height: 1.2;
    border: 1px solid transparent;
  }
  .provenance-tag[data-provenance="verified"] {
    background: #eefbf3;
    color: #14733b;
  }
  .provenance-tag[data-provenance="origin-bound"] {
    background: #f1f5eb;
    color: #4a6f2f;
  }
  .provenance-tag[data-provenance="caller"] {
    background: #fff7ed;
    color: #9a3412;
    border-color: #fdba74;
  }
  .metadata-reason,
  .reason-body,
  .reason-untrusted {
    overflow-wrap: anywhere;
    margin: 4px 0 0;
    font-size: 12px;
    line-height: 1.45;
    color: #475569;
  }
  .reason-untrusted {
    color: #9a3412;
  }
  .permissions {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .permissions-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .permissions-heading {
    font-size: 15px;
    font-weight: 700;
    margin: 0;
    color: #0f172a;
  }
  .permissions-actions {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
  }
  .link {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 12px;
    padding: 0;
    font-weight: 600;
    color: #334155;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .link:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .severity-bucket {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 12px;
    min-width: 0;
  }
  .bucket-summary {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 8px 12px;
    cursor: pointer;
    list-style: none;
  }
  .bucket-summary::-webkit-details-marker {
    display: none;
  }
  .bucket-summary::after {
    content: "▾";
    color: #64748b;
    flex: 0 0 auto;
    transition: transform 160ms ease;
  }
  .severity-bucket[open] > .bucket-summary::after {
    transform: rotate(180deg);
  }
  .bucket-content {
    margin-top: 10px;
  }
  .bucket-heading {
    font-size: 13px;
    font-weight: 700;
    margin: 0;
    color: #0f172a;
  }
  .bucket-hint {
    font-size: 11px;
    line-height: 1.35;
    color: #475569;
    margin: 0 0 0 auto;
    text-align: right;
  }
  .grant-list,
  .action-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .grant {
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 10px 12px;
    min-width: 0;
  }
  .grant-heading {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 8px;
    min-width: 0;
  }
  .grant-title {
    font-size: 13px;
    line-height: 1.45;
    font-weight: 600;
    color: #0f172a;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .grant-severity[data-severity="sensitive"] {
    color: #9f2424;
    font-weight: 600;
    font-size: 11px;
  }
  .grant-path {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin: 6px 0 0;
    min-width: 0;
  }
  .grant-service {
    color: #64748b;
    font-size: 11px;
    line-height: 1.2;
  }
  .grant-service[title],
  .grant-target[title] {
    cursor: help;
  }
  .grant-target {
    color: #334155;
    line-height: 1.35;
    overflow-wrap: anywhere;
    word-break: break-word;
  }
  .cross-app-warning {
    color: #9a3412;
    font-size: 12px;
    line-height: 1.45;
    margin: 6px 0 0;
    font-weight: 600;
  }
  .action-list {
    flex-direction: row;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 8px;
  }
  .action-toggle,
  .action-static {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    background: #fff;
    border: 1px solid #dbe2ea;
    font-size: 12px;
    line-height: 1.2;
  }
  .required-flag {
    color: #64748b;
    font-size: 10px;
  }
  .not-granting {
    margin: 7px 0 0;
    color: #64748b;
    font-size: 11px;
    line-height: 1.4;
  }
  .not-granting span {
    color: #475569;
    font-weight: 600;
  }
  .warnings {
    background: #fff7ed;
    border: 1px solid #fed7aa;
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 12px;
    color: #9a3412;
  }
  .warnings-heading {
    margin: 0 0 4px;
    font-size: 12px;
    font-weight: 700;
  }
  .warning {
    margin: 2px 0;
    line-height: 1.45;
  }
  .warning-code {
    background: #fff;
    padding: 1px 4px;
    border-radius: 3px;
    margin-right: 4px;
    font-size: 11px;
  }
  .raw {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .raw-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .raw-heading {
    font-size: 13px;
    font-weight: 700;
    margin: 0;
    color: #0f172a;
  }
  .copy-btn {
    background: #fff;
    border: 1px solid #cbd5e1;
    border-radius: 999px;
    padding: 6px 10px;
    font-size: 12px;
    font-weight: 600;
    line-height: 1.2;
    cursor: pointer;
    color: #334155;
    transition: background-color 120ms ease, border-color 120ms ease, color 120ms ease;
  }
  .copy-btn:hover {
    background: #f8fafc;
    border-color: #94a3b8;
    color: #0f172a;
  }
  .raw-bytes {
    background: #0f172a;
    color: #e2e8f0;
    padding: 12px;
    border-radius: 12px;
    overflow: auto;
    max-height: 180px;
    font-size: 12px;
    line-height: 1.5;
    white-space: pre;
    word-break: normal;
    user-select: text;
    -webkit-user-select: text;
  }
  .error {
    background: #fff7f7;
    color: #9f2424;
    padding: 8px 10px;
    border-radius: 10px;
    font-size: 12px;
    line-height: 1.45;
    margin: 0;
    border: 1px solid #f2c0c0;
  }
  .error-detail {
    color: #9f2424;
    font-size: 12px;
    line-height: 1.45;
    margin: -4px 0 0;
  }
  .error-detail summary {
    cursor: pointer;
  }
  .error-detail p {
    margin: 4px 0 0;
    overflow-wrap: anywhere;
  }
  .approve-blocked {
    color: #7c4a03;
    font-size: 12px;
    line-height: 1.45;
    margin: 0;
  }
  .actions {
    display: flex;
    gap: 10px;
  }
  .action-region {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .sticky-actions .action-region {
    position: sticky;
    bottom: 0;
    z-index: 1;
    gap: 8px;
    padding: 10px 0;
    background: #fff;
    box-shadow: 0 -8px 16px rgb(255 255 255 / 90%);
  }
  .cancel,
  .approve {
    flex: 1;
    padding: 10px 12px;
    border-radius: 12px;
    font-size: 14px;
    font-weight: 700;
    line-height: 1.2;
    cursor: pointer;
    border: 1px solid transparent;
  }
  .cancel {
    background: #fff;
    color: #0f172a;
    border-color: #cbd5e1;
  }
  .approve {
    background: #0f172a;
    color: #fff;
    border-color: #0f172a;
  }
  .cancel:hover {
    background: #f8fafc;
  }
  .dismiss-link {
    align-self: flex-start;
    padding: 4px 2px;
    background: none;
    border: 0;
    color: #475569;
    font-size: 13px;
    font-weight: 600;
    text-decoration: underline;
    cursor: pointer;
  }
  .dismiss-link:hover {
    color: #0f172a;
  }
  .dismiss-link:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .approve:hover {
    background: #111827;
  }
  .cancel:disabled,
  .approve:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  @media (max-width: 520px) {
    .signing-approval {
      width: calc(100% - 24px);
      padding: 14px;
      border-radius: 14px;
    }

    .row {
      flex-direction: column;
      align-items: flex-start;
    }

    .label {
      min-width: 0;
    }

    .permissions-header,
    .raw-header {
      align-items: flex-start;
    }

    .actions {
      flex-direction: column-reverse;
    }

    .cancel,
    .approve {
      width: 100%;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .signing-approval * {
      transition: none !important;
      animation: none !important;
    }
  }
</style>
