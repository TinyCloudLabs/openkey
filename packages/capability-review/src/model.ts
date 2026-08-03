// CapabilityReviewModel — the single presentation-safe DTO that every OpenKey
// authorization surface (CLI browser, popup, iframe) renders. Keeps protocol
// facts and presentation facts explicit so no Svelte component reverse-engineers
// trust from strings.
//
// Structural invariants:
//   - `rawMessage` is the exact bytes that will be signed (or a hint at what
//     WILL be signed after subset validation). Legacy signMessage callers must
//     always receive a signature over this exact string.
//   - `permissions[i].severity` starts from structural family/actions.
//     Generic metadata cannot lower it; the sole exception is the dedicated
//     exact app-scoped-secret proof gate (see app-scope.ts).
//   - `permissions[i].actions[j].required` marks actions whose removal would
//     break the delegation. UI must not let the user uncheck required actions.
//   - `metadataTrust.status` describes signed-manifest verification state.
//     Any status other than "verified" means presentation-only strings cannot
//     override structural classification.

export type PermissionSeverity = "standard" | "attention" | "sensitive";

export type MetadataTrustStatus =
  | "verified" // manifest signed by owner, digest matches, not stale
  | "origin-bound" // widget browser-verified the origin AND fetched the manifest at the well-known URL with a matching content digest — but no cryptographic manifest signature. Ranks between "unsigned" and "verified": presentation strings may hint but must never override structural severity.
  | "unsigned" // no manifest supplied
  | "stale" // manifest was signed but is past its refresh window
  | "wrong-key" // manifest signature did not verify against expected key
  | "digest-mismatch"; // manifest content hash did not match declared digest

export type CapabilityFamily =
  | "bootstrap-kv"
  | "bootstrap-sql"
  | "bootstrap-capabilities"
  | "bootstrap-delegation"
  | "own-app-data"
  | "cross-app-data"
  | "public-data"
  | "secret-read"
  | "secret-namespace-list"
  | "secret-mutation"
  | "encryption-key"
  | "encryption-decrypt"
  | "unknown";

/**
 * Stable action ID. Built by `ids.actionId(...)` from a NUL-separated
 * (service, space, path, action) tuple. Never construct manually — this is
 * the value the widget UI toggles and the API validates.
 */
export type ActionId = string;

/**
 * Stable permission (grant) ID. NUL-separated (service, space, path).
 */
export type PermissionId = string;

export interface CapabilityAction {
  /** Stable, exact-match ID. `ids.actionId(service, space, path, action)`. */
  id: ActionId;
  /**
   * The fully-qualified action namespace + verb, e.g.
   * `tinycloud.sql/read`, `tinycloud.kv/put`. This is the wire form the
   * SIWE ReCap actually carries. Do NOT split on `/` and reformat — the
   * verb sits after the namespace, which itself contains `.`.
   */
  ability: string;
  /**
   * Short verb (`read`, `write`, `admin`, `decrypt`, ...). Derived by
   * stripping the namespace prefix; used for compact UI labels.
   */
  verb: string;
  /** True when unchecking this action would break the delegation. */
  required: boolean;
  /** True when this action is currently selected for signing. */
  selected: boolean;
  /**
   * True when the user can toggle this action. Required actions are never
   * editable. Actions the CLI marked immutable are not editable either.
   */
  editable: boolean;
  /**
   * ReCap caveats attached to this (resource, ability) pair, preserved as
   * the exact JSON values parsed from the `urn:recap:` payload. An empty
   * array means "no caveats"; caveats narrow authority so removing them
   * server-side is a broadening violation. Subset validation compares
   * caveats structurally — the candidate must carry the SAME list, in the
   * SAME order, or be a documented subset (see subset.ts).
   *
   * Sol continuation contract: presence of ANY caveats disables /authorize-
   * sign narrowing because the current WASM emitter drops caveats when
   * regenerating a SIWE from an abilities map. The classifier / UI still
   * displays them for review.
   */
  caveats: unknown[];
}

export interface CapabilityGrant {
  /** Stable, exact-match ID. `ids.permissionId(service, space, path)`. */
  id: PermissionId;
  /** Structural family used by both classification and UI grouping. */
  family: CapabilityFamily;
  /** Structural severity, with only the proven app-scoped-secret exception. */
  severity: PermissionSeverity;
  /** Fully qualified service namespace, e.g. `tinycloud.kv`. */
  service: string;
  /** Space URI, e.g. `tinycloud:pkh:eip155:1:0x...:default`. */
  space: string;
  /** Path within the space. `""` for whole-space grants. */
  path: string;
  /** Owner of the addressed resource, when derivable from the space URI. */
  owner: string | null;
  /** True when `owner` matches the account signing this request. */
  ownedBySelf: boolean | null;
  /** Verified, human-safe label. Never overrides `severity`. */
  displayLabel: string;
  /**
   * Optional supplementary label supplied by the manifest. Rendered as
   * hint text only when `metadataTrust.status === "verified"`.
   */
  metadataLabel: string | null;
  /**
   * Present only after the dedicated app-scope proof gate has matched an
   * origin-bound (or verified) manifest declaration to the exact signed
   * secret name, scope, and requested actions. This is structural review
   * state, not caller-supplied display metadata.
   */
  appScopedSecret?: {
    secretName: string;
    scope?: string;
  };
  /**
   * Blocker 4 (Defect 2): true when a grant STRUCTURALLY looks like an
   * attempt at an app-scoped secret (KV service on a secrets-shaped space
   * with a secret-family classification) but FAILED the exact-resource
   * proof — for example a cross-signer secrets space, a non-canonical
   * vault path, or a mismatched declared entry. `annotateAppScopedGrants`
   * sets this flag to force `buildStatement` to render the literal
   * fallback copy (raw service/resource/actions) instead of the friendly
   * "View secrets stored in your vault" wording the KV secrets branch
   * would otherwise emit. This closes the near-miss gap where a grant
   * that never earned an app-scope label still inherited friendly
   * secret-family copy at attention severity.
   *
   * The flag is a demote-only signal: it never lowers severity, and
   * `annotateAppScopedGrants` always pairs it with an explicit
   * `severity = "sensitive"` reset so the operator sees the elevated
   * severity next to the literal fallback copy.
   */
  appScopeNearMiss?: boolean;
  /**
   * Blocker 4 follow-up (Defect 5): the short-service segment as it
   * appeared in the resource URI portion of the wire (`kv` from
   * `<space>/kv/vault/secrets/...`). Preserved SEPARATELY from
   * `service` (which is derived from the ability head, e.g.
   * `tinycloud.kv` from `tinycloud.kv/get`) so downstream gates can
   * detect wire-shape mismatches where the ability service and the
   * resource-side short-service segment disagree.
   *
   * Null when the parsed input carried no resource-side short-service
   * segment (bare `<space>` resource URI, or the legacy expanded form
   * where the service is entirely implied by the ability head).
   */
  resourceService: string | null;
  /**
   * Blocker 4 follow-up (Defect 5): true when the ability-derived
   * `service` disagrees with the resource-derived `resourceService`
   * segment on any ability inside this ATT entry (for example, a
   * resource URI of `<space>/sql/vault/secrets/scoped/listen/API_KEY`
   * with an ability of `tinycloud.kv/get`).
   *
   * This is a demote-only signal: `annotateAppScopedGrants` will never
   * annotate a service-mismatched grant with `appScopedSecret`, and
   * `buildStatement` short-circuits any grant carrying this flag to
   * the literal fallback so friendly copy is never rendered on a
   * wire-shape mismatch that the operator ought to see verbatim.
   */
  serviceMismatch?: boolean;
  /** Actions granted for this resource. */
  actions: CapabilityAction[];
}

export interface RequesterIdentity {
  /**
   * Display name shown in the small summary. Widget callers must use only an
   * origin-bound/verified manifest name or the browser authority here. A
   * caller-echoed envelope name belongs in `manifestName` with `caller`
   * provenance so it stays explicitly labelled in Advanced details.
   */
  displayName: string;
  /**
   * Verified origin of the request (the SIWE `domain` field, or the
   * postMessage origin). Never a caller-supplied "app name".
   */
  verifiedOrigin: string | null;
  /**
   * Sol minor: the manifest's `app_id`. Distinct from `manifestId`
   * (which is the versioned manifest identifier / registry ID). The
   * Advanced details disclosure renders these as SEPARATE fields so
   * the operator can distinguish "which app is this?" from "which
   * manifest version am I looking at?". Null when the origin-bound
   * manifest did not carry an `app_id`.
   */
  appId: string | null;
  /**
   * Sol MAJOR-4: manifest `name` field with honest provenance.
   *
   *   - `manifestName` carries the raw string OpenKey stored — never
   *     interpret this as trusted on its own.
   *   - `manifestNameProvenance` describes where the string came from:
   *       - `"verified"` — the string was pulled from a signed manifest.
   *       - `"origin-bound"` — the string came from a well-known manifest
   *         at the reported origin whose digest matched the caller-
   *         supplied envelope. The origin bound the string, but no
   *         cryptographic signature attests it.
   *       - `"caller"` — the string is a caller-supplied envelope value
   *         that OpenKey could NOT verify (unsigned, no origin-bind, or
   *         the origin-bind manifest omitted `name`). It MUST be
   *         rendered with a visible "unverified" hint.
   *       - `"none"` — no manifest name is available.
   *
   * The Advanced details disclosure renders the name AND its
   * provenance as separate fields so the operator can never mistake
   * a caller-echoed name for a cryptographically-verified label.
   */
  manifestName: string | null;
  manifestNameProvenance: "verified" | "origin-bound" | "caller" | "none";
  /**
   * Manifest ID and content digest, when available. `manifestIdProvenance`
   * mirrors the `manifestName` provenance rule: OpenKey MUST NOT label a
   * caller-supplied `manifestId` as origin-bound just because the
   * envelope was successfully bound to some other field.
   */
  manifestId: string | null;
  manifestIdProvenance: "verified" | "origin-bound" | "caller" | "none";
  manifestDigest: string | null;
  /** True when domain/origin/manifest disagree. */
  domainWarning: boolean;
  /** True when the SIWE domain does not match `verifiedOrigin`. */
  originWarning: boolean;
}

export interface ReasonProvenance {
  /** The raw reason string, if present. Always displayed as untrusted context. */
  text: string;
  /** Where the string came from. `manifest` is trusted; `caller` is not. */
  source: "manifest" | "caller" | "none";
}

export interface SignerInfo {
  /** Human label, e.g. "MetaMask account". */
  label: string;
  /** EIP-55 encoded address. */
  address: string;
  /** Chain ID, EIP-155. */
  chainId: number;
  /**
   * Whether this signer is managed by OpenKey (TEE sealed) or external
   * (browser wallet). Governs downstream completion path.
   */
  provenance: "managed" | "external";
}

/**
 * Fields the user MUST NOT be able to change. `assertImmutableFieldsUnchanged`
 * on the server rejects any deviation from the values captured here.
 */
export interface ImmutableSiweFields {
  address: string;
  chainId: number;
  domain: string;
  issuedAt: string;
  expirationTime: string;
  spaceId: string;
  jwk: unknown;
  /** Full nonce line from the SIWE. */
  nonce: string;
}

export interface MetadataTrust {
  status: MetadataTrustStatus;
  /**
   * Human-friendly reason. UI may display this next to the manifest name;
   * it never overrides structural severity.
   */
  reason: string;
}

/**
 * Parser warnings surfaced to the UI so the operator sees exactly what the
 * model could not classify. Never silent.
 */
export interface ParseWarning {
  code:
    | "unknown-service"
    | "malformed-space"
    | "no-recap"
    | "duplicate-action"
    | "unrecognized-recap-namespace"
    | "unparseable-siwe";
  message: string;
  hint?: string;
}

export type RequestProtocol =
  /** Legacy signMessage(bytes) — no editing, byte-exact sign. */
  | "legacy-message"
  /** Ordinary SIWE — no ReCap, no editing. */
  | "siwe-plain"
  /** TinyCloud SIWE with ReCap — editable subject to invariants. */
  | "tinycloud-siwe-recap"
  /**
   * A SIWE that carried a `urn:recap:` resource whose payload was
   * unparseable / produced zero entries. This is NOT the same as plain
   * SIWE — a plain SIWE has no ReCap at all. A malformed ReCap looks
   * ReCap-shaped but decoded to nothing, so treating it as `siwe-plain`
   * would let the widget approve exact-byte signing of a message whose
   * capability payload was silently ignored. UI MUST refuse to approve
   * this protocol; the request has to be rejected.
   */
  | "malformed-recap";

export interface CapabilityReviewModel {
  /** Version tag so consumers can detect breaking model changes. */
  version: 1;
  /** How this request should be treated (edit or byte-exact). */
  protocol: RequestProtocol;
  /**
   * Exact bytes that will be signed. For legacy-message this is the input.
   * For editable flows this is the CURRENT bytes (regenerated after subset
   * validation each time selections change).
   */
  rawMessage: string;
  requester: RequesterIdentity;
  reason: ReasonProvenance;
  signer: SignerInfo;
  /**
   * ISO-8601 expiry the delegation will assume. Comes from SIWE Expiration
   * Time when parseable; falls back to caller-supplied `expiry`.
   */
  expiry: string | null;
  immutable: ImmutableSiweFields | null;
  metadataTrust: MetadataTrust;
  permissions: CapabilityGrant[];
  parseWarnings: ParseWarning[];
}
