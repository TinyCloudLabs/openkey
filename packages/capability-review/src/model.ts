// CapabilityReviewModel — the single presentation-safe DTO that every OpenKey
// authorization surface (CLI browser, popup, iframe) renders. Keeps protocol
// facts and presentation facts explicit so no Svelte component reverse-engineers
// trust from strings.
//
// Structural invariants:
//   - `rawMessage` is the exact bytes that will be signed (or a hint at what
//     WILL be signed after subset validation). Legacy signMessage callers must
//     always receive a signature over this exact string.
//   - `permissions[i].severity` is derived from structural family/actions
//     ONLY. Metadata cannot lower it (see metadata.ts monotonicity).
//   - `permissions[i].actions[j].required` marks actions whose removal would
//     break the delegation. UI must not let the user uncheck required actions.
//   - `metadataTrust.status` describes signed-manifest verification state.
//     Any status other than "verified" means presentation-only strings cannot
//     override structural classification.

export type PermissionSeverity = "standard" | "attention" | "sensitive";

export type MetadataTrustStatus =
  | "verified" // manifest signed by owner, digest matches, not stale
  | "unsigned" // no manifest supplied
  | "stale" // manifest was signed but is past its refresh window
  | "wrong-key" // manifest signature did not verify against expected key
  | "digest-mismatch"; // manifest content hash did not match declared digest

export type CapabilityFamily =
  | "bootstrap-kv"
  | "bootstrap-sql"
  | "bootstrap-capabilities"
  | "own-app-data"
  | "cross-app-data"
  | "secret-read"
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
}

export interface CapabilityGrant {
  /** Stable, exact-match ID. `ids.permissionId(service, space, path)`. */
  id: PermissionId;
  /** Structural family used by both classification and UI grouping. */
  family: CapabilityFamily;
  /** Structural severity. Cannot be lowered by presentation metadata. */
  severity: PermissionSeverity;
  /** Fully qualified service namespace, e.g. `tinycloud.kv`. */
  service: string;
  /** Space URI, e.g. `tinycloud:pkh:eip155:1:0x...:default`. */
  space: string;
  /** Path within the space. `""` for whole-space grants. */
  path: string;
  /** Owner of the addressed resource, when derivable from the space URI. */
  owner: string | null;
  /** True when `owner` matches the requesting app / user, false when cross-app. */
  ownedBySelf: boolean | null;
  /** Verified, human-safe label. Never overrides `severity`. */
  displayLabel: string;
  /**
   * Optional supplementary label supplied by the manifest. Rendered as
   * hint text only when `metadataTrust.status === "verified"`.
   */
  metadataLabel: string | null;
  /** Actions granted for this resource. */
  actions: CapabilityAction[];
}

export interface RequesterIdentity {
  /** Display name from the manifest, or origin fallback. */
  displayName: string;
  /**
   * Verified origin of the request (the SIWE `domain` field, or the
   * postMessage origin). Never a caller-supplied "app name".
   */
  verifiedOrigin: string | null;
  /** Manifest ID and content digest, when available. */
  manifestId: string | null;
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
  | "tinycloud-siwe-recap";

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
