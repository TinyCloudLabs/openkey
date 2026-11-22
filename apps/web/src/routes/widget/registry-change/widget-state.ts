// TC-3893: pure state machine, diff builder, and Monica's final copy constants
// (tc3890-wording-monica.md §1, follow-up 16:30Z, restore-any-version 16:31Z,
// F3/F5/F6/F8 review copy 16:49Z-16:54Z) for the registry-change & undo/restore
// consent screen on both popup (`/widget/registry-change`) and embed
// (`/widget/embed/registry-change`).

export const TINYCLOUD_ONE_ORIGINS: ReadonlySet<string> = new Set([
  'https://tinycloud.one',
  'https://home.tinycloud.xyz',
]);

function requesterLabel(origin: string): string {
  return TINYCLOUD_ONE_ORIGINS.has(origin) ? 'TinyCloud One' : origin;
}

/** F8: format dates with the user's locale (`toLocaleDateString`), matching TinyCloud One. */
export function formatLocaleDate(iso: string | null, locale?: string): string {
  if (!iso) return '';
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso.slice(0, 10);
  return parsed.toLocaleDateString(locale);
}

export const REGISTRY_CHANGE_COPY = {
  title: 'Move where your data lives?',
  undoTitle: 'Undo the last change?',
  restoreTitle: 'Restore an earlier version?',
  originLine: (origin: string) => `${origin} wants to change where your data lives.`,
  undoOriginLine: (origin: string) =>
    `${requesterLabel(origin)} wants to undo the last change to where your data lives.`,
  restoreOriginLine: (origin: string, dateIso: string | null, locale?: string) =>
    `${requesterLabel(origin)} wants to put back where your data lived before ${formatLocaleDate(dateIso, locale)}.`,
  explainer:
    "After you approve, your apps save and read your data on the hosts below. Data already saved stays where it is, and these apps won't show it until you move back.",
  riskLine: 'Whoever runs a new host can read what you save there. Approve only if you trust it.',
  tableHeader: {
    space: 'Space',
    before: 'Where it is',
    after: 'Where it would be',
  },
  noChange: 'No change',
  notSet: 'Not set',
  modeReadOnly: 'read-only',
  modeReadWrite: 'read and write',
  encryptionRowLabel: 'Secrets and keys',
  encryptionChangedLine: (host: string) =>
    `New secrets and keys will be held at ${host}. Whoever runs it can open secrets you save after this.`,
  encryptionClearedLine:
    "Your secrets and keys would have no host. Apps can't open or save your encrypted data until one is set.",
  identityUnreachable: (host: string) => `Couldn't reach ${host} to confirm what it is.`,
  identityMismatch: (host: string) => `${host} doesn't match the identity it was listed with.`,
  identityWarningFooter: 'You can approve anyway, but check this host with whoever asked you to move.',
  nodeDidRequiredPopup: (host: string) =>
    `Couldn't reach ${host} to confirm which host it is, so nothing was changed. The app that asked needs to fix this; you can close this window.`,
  nodeDidRequiredEmbed: (host: string) =>
    `Couldn't reach ${host} to confirm which host it is, so nothing was changed. The app that asked needs to fix this; you can go back to the app.`,
  approveButton: 'Approve with passkey',
  approvingButton: 'Approving…',
  cancelButton: 'Cancel',
  loading: 'Checking your current settings…',
  waiting: "Waiting for the app's request…",
  passkeyPromptReason: 'Confirm moving where your data lives',
  staleTitle: 'This changed while you were looking',
  staleBody: "Your data's location was updated somewhere else. Review the new details before you approve.",
  staleButton: 'Review again',
  success: 'Done. Your apps use the new hosts from their next sign-in.',
  failure: "Couldn't change this. Nothing was changed. Try again.",
  refusedUrl: "This request lists a node address OpenKey can't read, so nothing was signed.",
  missingRecord: 'No location is set for your account.',
  historyNotFound: "Couldn't find that earlier version. Nothing was changed.",
  rateLimited: 'Too many tries. Nothing was changed. Try again in a few minutes.',
  passkeyRequiredToUse: 'Add a passkey to your OpenKey account to change where your data lives.',
} as const;

export type RegistryChangePhase =
  | 'waiting'
  | 'preparing'
  | 'review'
  | 'submitting'
  | 'stale'
  | 'invalid'
  | 'error'
  | 'done'
  | 'cancelled'
  | 'embedded-refused';

export type RegistryChangeMode = 'change' | 'undo';
export type RegistryUndoKind = 'undo-last' | 'restore';
export type RegistryWidgetSurface = 'popup' | 'embed';

export interface RegistryRecordPayloadView {
  version: 2;
  subject: string;
  nodes: Array<{ did: string; url: string }>;
  spaces: Array<{ space: string; nodes: Array<{ did: string; mode: 'read-write' | 'read-only' }> }>;
  encryptionNode: string | null;
  updated_at: string;
  sequence: number;
}

export interface NodeIdentityView {
  url: string;
  did: string | null;
  status: 'ok' | 'mismatch' | 'unreachable';
}

export interface PasskeyOfferView {
  required: true;
  challengeToken: string;
  options: unknown;
}

export interface PrepareResponseBody {
  changeId: string;
  requestingOrigin: string;
  before: RegistryRecordPayloadView;
  after: RegistryRecordPayloadView;
  recordHash: string;
  identity: NodeIdentityView[];
  encryptionChanged: boolean;
  passkey: PasskeyOfferView;
  undoKind?: RegistryUndoKind;
  restoredBeforeDate?: string;
}

export interface PublishResponseBody {
  sequence: number;
  recordHash: string;
}

export interface RegistryChangeDiffRow {
  label: string;
  beforeHost: string;
  afterHost: string;
  changed: boolean;
  isEncryption: boolean;
  /** Present on a single-host mode-only change: "{space}: {host}, read-only → read and write". */
  modeOnlyLine?: string;
}

export interface IdentityWarningItem {
  url: string;
  host: string;
  status: 'unreachable' | 'mismatch';
  message: string;
}

export interface RegistryChangePostBack {
  type: 'openkey:registry-change:response';
  requestId: string;
  protocolVersion: 1;
  success: true;
  status: 'published' | 'cancelled';
  sequence?: number;
  recordHash?: string;
}

export interface RegistryChangeWidgetState {
  phase: RegistryChangePhase;
  mode: RegistryChangeMode;
  undoKind: RegistryUndoKind | null;
  restoredBeforeDate: string | null;
  requestId: string | null;
  verifiedRequestingOrigin: string | null;
  requestPayload: Record<string, unknown> | null;
  historyId: string | null;
  changeId: string | null;
  before: RegistryRecordPayloadView | null;
  after: RegistryRecordPayloadView | null;
  recordHash: string | null;
  identity: NodeIdentityView[];
  encryptionChanged: boolean;
  encryptionBeforeHost: string | null;
  encryptionAfterHost: string | null;
  diffRows: RegistryChangeDiffRow[];
  warnings: IdentityWarningItem[];
  passkey: PasskeyOfferView | null;
  error: string | null;
}

export function initialState(embeddedRefusalMessage: string | null): RegistryChangeWidgetState {
  return {
    phase: embeddedRefusalMessage ? 'embedded-refused' : 'waiting',
    mode: 'change',
    undoKind: null,
    restoredBeforeDate: null,
    requestId: null,
    verifiedRequestingOrigin: null,
    requestPayload: null,
    historyId: null,
    changeId: null,
    before: null,
    after: null,
    recordHash: null,
    identity: [],
    encryptionChanged: false,
    encryptionBeforeHost: null,
    encryptionAfterHost: null,
    diffRows: [],
    warnings: [],
    passkey: null,
    error: embeddedRefusalMessage,
  };
}

export function screenTitle(state: Pick<RegistryChangeWidgetState, 'mode' | 'undoKind'>): string {
  if (state.mode === 'undo') {
    return state.undoKind === 'undo-last'
      ? REGISTRY_CHANGE_COPY.undoTitle
      : REGISTRY_CHANGE_COPY.restoreTitle;
  }
  return REGISTRY_CHANGE_COPY.title;
}

export function screenOriginLine(
  state: Pick<RegistryChangeWidgetState, 'mode' | 'undoKind' | 'verifiedRequestingOrigin' | 'restoredBeforeDate'>,
  locale?: string,
): string | null {
  if (!state.verifiedRequestingOrigin) return null;
  if (state.mode === 'undo') {
    return state.undoKind === 'undo-last'
      ? REGISTRY_CHANGE_COPY.undoOriginLine(state.verifiedRequestingOrigin)
      : REGISTRY_CHANGE_COPY.restoreOriginLine(state.verifiedRequestingOrigin, state.restoredBeforeDate, locale);
  }
  return REGISTRY_CHANGE_COPY.originLine(state.verifiedRequestingOrigin);
}

/** Canonical host for display (includes non-default ports, raw IPv4, bracketed IPv6). */
export function formatDisplayHost(rawUrl: string): string {
  try {
    return new URL(rawUrl).host;
  } catch {
    return rawUrl;
  }
}

export function formatSpaceName(spaceUri: string): string {
  const idx = spaceUri.lastIndexOf(':');
  return idx >= 0 && idx + 1 < spaceUri.length ? spaceUri.slice(idx + 1) : spaceUri;
}

function modeLabel(mode: string): string {
  return mode === 'read-only'
    ? REGISTRY_CHANGE_COPY.modeReadOnly
    : REGISTRY_CHANGE_COPY.modeReadWrite;
}

type ResolvedMembership = { host: string; mode: string };

function resolveMemberships(
  memberships: ReadonlyArray<{ did: string; mode: string }> | undefined,
  urlByDid: ReadonlyMap<string, string>,
): ResolvedMembership[] {
  if (!memberships) return [];
  return memberships
    .map((m) => {
      const url = urlByDid.get(m.did);
      return { host: url ? formatDisplayHost(url) : m.did, mode: m.mode };
    })
    .sort((a, b) => a.host.localeCompare(b.host) || a.mode.localeCompare(b.mode));
}

function membershipsEqual(a: ResolvedMembership[], b: ResolvedMembership[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((item, i) => item.host === b[i]!.host && item.mode === b[i]!.mode);
}

function hostsOnlyEqual(a: ResolvedMembership[], b: ResolvedMembership[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((item, i) => item.host === b[i]!.host);
}

function formatMemberships(memberships: ResolvedMembership[], showModes: boolean): string {
  if (memberships.length === 0) return REGISTRY_CHANGE_COPY.notSet;
  return memberships
    .map((m) => (showModes ? `${m.host} (${modeLabel(m.mode)})` : m.host))
    .join(', ');
}

export function buildDiffView(
  before: RegistryRecordPayloadView,
  after: RegistryRecordPayloadView,
  encryptionChanged: boolean,
): {
  diffRows: RegistryChangeDiffRow[];
  encryptionBeforeHost: string | null;
  encryptionAfterHost: string | null;
} {
  const beforeUrls = new Map(before.nodes.map((n) => [n.did, n.url]));
  const afterUrls = new Map(after.nodes.map((n) => [n.did, n.url]));
  const beforeSpaces = new Map(before.spaces.map((s) => [s.space, s.nodes]));
  const afterSpaces = new Map(after.spaces.map((s) => [s.space, s.nodes]));

  const allSpaceUris = [...new Set([...beforeSpaces.keys(), ...afterSpaces.keys()])].sort();
  const diffRows: RegistryChangeDiffRow[] = allSpaceUris.map((spaceUri) => {
    const beforeMem = resolveMemberships(beforeSpaces.get(spaceUri), beforeUrls);
    const afterMem = resolveMemberships(afterSpaces.get(spaceUri), afterUrls);
    const changed = !membershipsEqual(beforeMem, afterMem);
    const sameHosts = hostsOnlyEqual(beforeMem, afterMem);
    const showModes =
      (changed && sameHosts) ||
      beforeMem.some((m) => m.mode === 'read-only') ||
      afterMem.some((m) => m.mode === 'read-only');

    const label = formatSpaceName(spaceUri);
    const beforeHost = formatMemberships(beforeMem, showModes);
    const afterHost = changed ? formatMemberships(afterMem, showModes) : REGISTRY_CHANGE_COPY.noChange;

    const modeOnlyLine =
      changed && sameHosts && beforeMem.length === 1 && afterMem.length === 1
        ? `${label}: ${beforeMem[0]!.host}, ${modeLabel(beforeMem[0]!.mode)} → ${modeLabel(afterMem[0]!.mode)}`
        : undefined;

    return {
      label,
      beforeHost,
      afterHost,
      changed,
      isEncryption: false,
      ...(modeOnlyLine ? { modeOnlyLine } : {}),
    };
  });

  const encBeforeUrl = before.encryptionNode ? beforeUrls.get(before.encryptionNode) ?? null : null;
  const encAfterUrl = after.encryptionNode ? afterUrls.get(after.encryptionNode) ?? null : null;
  const encryptionBeforeHost = encBeforeUrl ? formatDisplayHost(encBeforeUrl) : null;
  const encryptionAfterHost = encAfterUrl ? formatDisplayHost(encAfterUrl) : null;

  if (encryptionChanged || encryptionBeforeHost !== null || encryptionAfterHost !== null) {
    diffRows.push({
      label: REGISTRY_CHANGE_COPY.encryptionRowLabel,
      beforeHost: encryptionBeforeHost ?? REGISTRY_CHANGE_COPY.notSet,
      afterHost: encryptionChanged
        ? (encryptionAfterHost ?? REGISTRY_CHANGE_COPY.notSet)
        : REGISTRY_CHANGE_COPY.noChange,
      changed: encryptionChanged,
      isEncryption: true,
    });
  }

  return { diffRows, encryptionBeforeHost, encryptionAfterHost };
}

export function buildIdentityWarnings(identity: ReadonlyArray<NodeIdentityView>): IdentityWarningItem[] {
  const warnings: IdentityWarningItem[] = [];
  for (const item of identity) {
    if (item.status === 'ok') continue;
    const host = formatDisplayHost(item.url);
    warnings.push({
      url: item.url,
      host,
      status: item.status,
      message: item.status === 'unreachable'
        ? REGISTRY_CHANGE_COPY.identityUnreachable(host)
        : REGISTRY_CHANGE_COPY.identityMismatch(host),
    });
  }
  return warnings;
}

/**
 * Capture the incoming `openkey:registry-change:request` or `openkey:registry-undo:request`
 * message from the verified counterparty (`window.opener` for popup, `window.parent` for embed).
 *
 * Security invariants:
 *   - `verifiedRequestingOrigin` is captured EXCLUSIVELY from `event.origin`, NEVER from
 *     any field inside `event.data` or `event.data.request`.
 *   - Once sealed on the first valid request, a second request cannot overwrite state.
 */
export function applyRequestMessage(
  state: RegistryChangeWidgetState,
  event: {
    origin: string;
    source: unknown;
    counterparty: unknown;
    configuredOrigin: string | null;
    data: unknown;
  },
): RegistryChangeWidgetState {
  if (state.phase !== 'waiting') return state;
  if (!event.counterparty || event.source !== event.counterparty) return state;
  if (!event.origin || event.origin === 'null') return state;
  if (event.configuredOrigin !== null && event.origin !== event.configuredOrigin) return state;
  if (!event.data || typeof event.data !== 'object' || Array.isArray(event.data)) return state;

  const data = event.data as Record<string, unknown>;
  if (data.protocolVersion !== 1) return state;
  if (typeof data.requestId !== 'string' || data.requestId.length === 0) return state;

  if (data.type === 'openkey:registry-undo:request') {
    if (typeof data.historyId !== 'string' || data.historyId.length === 0) return state;
    return {
      ...state,
      phase: 'preparing',
      mode: 'undo',
      requestId: data.requestId,
      verifiedRequestingOrigin: event.origin,
      historyId: data.historyId,
      requestPayload: null,
      error: null,
    };
  }

  if (data.type !== 'openkey:registry-change:request') return state;
  if (!data.request || typeof data.request !== 'object' || Array.isArray(data.request)) return state;

  // Strip only the exact narrow fields of the request; ignore any origin/requestingOrigin fields.
  const rawReq = data.request as Record<string, unknown>;
  const sanitizedRequest: Record<string, unknown> = {
    nodes: rawReq.nodes,
    ...(rawReq.spaces !== undefined ? { spaces: rawReq.spaces } : {}),
    ...(rawReq.encryptionNode !== undefined ? { encryptionNode: rawReq.encryptionNode } : {}),
  };

  return {
    ...state,
    phase: 'preparing',
    mode: 'change',
    requestId: data.requestId,
    verifiedRequestingOrigin: event.origin,
    requestPayload: sanitizedRequest,
    historyId: null,
    error: null,
  };
}

export function applyPrepareResult(
  state: RegistryChangeWidgetState,
  result:
    | { ok: true; body: PrepareResponseBody }
    | { ok: false; status: number; body: { error?: string; code?: string; host?: string; message?: string } },
  surface: RegistryWidgetSurface = 'popup',
): RegistryChangeWidgetState {
  if (result.ok) {
    const { diffRows, encryptionBeforeHost, encryptionAfterHost } = buildDiffView(
      result.body.before,
      result.body.after,
      result.body.encryptionChanged,
    );
    const warnings = buildIdentityWarnings(result.body.identity);
    return {
      ...state,
      phase: 'review',
      undoKind: state.mode === 'undo' ? (result.body.undoKind ?? 'restore') : null,
      restoredBeforeDate: state.mode === 'undo' ? (result.body.restoredBeforeDate ?? null) : null,
      changeId: result.body.changeId,
      before: result.body.before,
      after: result.body.after,
      recordHash: result.body.recordHash,
      identity: result.body.identity,
      encryptionChanged: result.body.encryptionChanged,
      encryptionBeforeHost,
      encryptionAfterHost,
      diffRows,
      warnings,
      passkey: result.body.passkey,
      error: null,
    };
  }

  const code = result.body.code ?? result.body.error;
  if (result.status === 422 && code === 'registry_change_node_did_required') {
    const host = result.body.host || 'that host';
    const message = surface === 'embed'
      ? REGISTRY_CHANGE_COPY.nodeDidRequiredEmbed(host)
      : REGISTRY_CHANGE_COPY.nodeDidRequiredPopup(host);
    return { ...state, phase: 'error', error: message };
  }
  if (result.status === 400 && code === 'registry_change_invalid_node') {
    return { ...state, phase: 'invalid', error: REGISTRY_CHANGE_COPY.refusedUrl };
  }
  if (result.status === 404 && code === 'history_not_found') {
    return { ...state, phase: 'error', error: REGISTRY_CHANGE_COPY.historyNotFound };
  }
  if (result.status === 409 && code === 'registry_record_missing') {
    return { ...state, phase: 'error', error: REGISTRY_CHANGE_COPY.missingRecord };
  }
  if (result.status === 429) {
    return { ...state, phase: 'error', error: REGISTRY_CHANGE_COPY.rateLimited };
  }
  if (result.status === 403 && code === 'passkey_approval_required') {
    return { ...state, phase: 'error', error: REGISTRY_CHANGE_COPY.passkeyRequiredToUse };
  }
  return { ...state, phase: 'error', error: REGISTRY_CHANGE_COPY.failure };
}

export function applyPublishResult(
  state: RegistryChangeWidgetState,
  result:
    | { ok: true; body: PublishResponseBody }
    | { ok: false; status: number; body: { error?: string; code?: string; message?: string } },
): { state: RegistryChangeWidgetState; postBack: RegistryChangePostBack | null; needsReprepare?: boolean } {
  if (result.ok) {
    return {
      state: { ...state, phase: 'done', error: null },
      postBack: state.requestId
        ? {
            type: 'openkey:registry-change:response',
            requestId: state.requestId,
            protocolVersion: 1,
            success: true,
            status: 'published',
            sequence: result.body.sequence,
            recordHash: result.body.recordHash,
          }
        : null,
    };
  }

  const code = result.body.code ?? result.body.error;
  if (result.status === 409 && code === 'registry_change_stale') {
    return {
      state: { ...state, phase: 'stale', error: null },
      postBack: null,
    };
  }
  if (result.status === 429) {
    return {
      state: { ...state, phase: 'review', error: REGISTRY_CHANGE_COPY.rateLimited },
      postBack: null,
    };
  }
  if (
    result.status === 403 &&
    (code === 'passkey_approval_required' || code === 'passkey_approval_invalid' || code === 'passkey_not_step_up_capable')
  ) {
    return {
      state: { ...state, phase: 'preparing', error: result.body.message ?? REGISTRY_CHANGE_COPY.failure },
      postBack: null,
      needsReprepare: true,
    };
  }

  return {
    state: { ...state, phase: 'review', error: REGISTRY_CHANGE_COPY.failure },
    postBack: null,
  };
}

export function applyCancel(state: RegistryChangeWidgetState): {
  state: RegistryChangeWidgetState;
  postBack: RegistryChangePostBack | null;
} {
  return {
    state: { ...state, phase: 'cancelled' },
    postBack: state.requestId
      ? {
          type: 'openkey:registry-change:response',
          requestId: state.requestId,
          protocolVersion: 1,
          success: true,
          status: 'cancelled',
        }
      : null,
  };
}
