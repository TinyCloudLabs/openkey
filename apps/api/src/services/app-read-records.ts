// Read-only decoder copied from web-sdk packages/sdk-core/src/account/applicationRecords.ts
// in the command-friction candidate. No legacy migration or writes are included.
// The API's pinned sdk-core 2.6.1 predates the public account decoder export.
import { validateManifest, type Manifest } from '@tinycloud/sdk-core';
const ACCOUNT_REGISTRY_PATH = 'applications/';
type ServiceError = { code: string; message: string; meta?: Record<string, unknown> };
type Result<T> = { ok: true; data: T } | { ok: false; error: ServiceError };
const ok = <T>(data: T): Result<T> => ({ ok: true, data });
const err = (error: ServiceError): Result<never> => ({ ok: false, error });
const serviceError = (code: string, message: string, _service: string, options: {meta: Record<string, unknown>}): ServiceError => ({ code, message, ...options });

export interface AccountApplication {
  appId: string;
  manifests: Manifest[];
  updatedAt?: string;
  name?: string;
  description?: string;
  manifestHash?: string;
}

export interface AccountApplicationIssue {
  key: string;
  code:
    | "INVALID_APPLICATION_RECORD"
    | "LEGACY_APPLICATION_RECORD"
    | "APPLICATION_RECORD_MISSING"
    | "APPLICATION_REGISTRY_INCOMPLETE";
  category:
    | "invalid_json"
    | "invalid_shape"
    | "invalid_manifest"
    | "identity_mismatch"
    | "invalid_metadata"
    | "hash_mismatch"
    | "legacy"
    | "missing"
    | "truncated";
  field: string;
}

export interface AccountApplicationListing {
  applications: AccountApplication[];
  issues: AccountApplicationIssue[];
  /** False means absence of an application cannot be inferred from this listing. */
  complete: boolean;
}

/** Safe to expose: errors retain only the canonical key, category, and field. */
export function applicationRecordError(
  issue: AccountApplicationIssue,
): ServiceError {
  return serviceError(
    issue.code,
    `Application record ${issue.key}: ${issue.category} (${issue.field})`,
    "account",
    {
      meta: { key: issue.key, category: issue.category, field: issue.field },
    },
  );
}

/** Decode canonical records independent of their KV response MIME type. */
export function decodeApplicationRecord(
  key: string,
  input: unknown,
): Result<AccountApplication> {
  const invalid = (
    category: AccountApplicationIssue["category"],
    field: string,
    code: AccountApplicationIssue["code"] = "INVALID_APPLICATION_RECORD",
  ) => err(applicationRecordError({ key, code, category, field }));
  let value = input;
  if (typeof value === "string") {
    try {
      value = JSON.parse(value);
    } catch {
      return invalid("invalid_json", "$");
    }
  }
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return invalid("invalid_shape", "$");
  const record = value as Record<string, unknown>;
  if ("manifest" in record)
    return invalid("legacy", "manifest", "LEGACY_APPLICATION_RECORD");
  if (!Array.isArray(record.manifests) || record.manifests.length === 0)
    return invalid("invalid_shape", "manifests");
  const appId = key.startsWith(ACCOUNT_REGISTRY_PATH)
    ? key.slice(ACCOUNT_REGISTRY_PATH.length)
    : "";
  if (!appId || appId.includes("/") || appId.includes("*"))
    return invalid("identity_mismatch", "key");
  for (const name of ["app_id", "appId"]) {
    if (record[name] !== undefined && record[name] !== appId)
      return invalid("identity_mismatch", "app_id");
  }
  for (const [snake, camel] of [
    ["updated_at", "updatedAt"],
    ["manifest_hash", "manifestHash"],
    ["name", "name"],
    ["description", "description"],
  ]) {
    for (const name of [snake!, camel!]) {
      if (record[name] !== undefined && typeof record[name] !== "string")
        return invalid("invalid_metadata", snake!);
    }
    if (
      record[snake!] !== undefined &&
      record[camel!] !== undefined &&
      record[snake!] !== record[camel!]
    )
      return invalid("invalid_metadata", snake!);
  }
  const updatedAt = (record.updated_at ?? record.updatedAt) as
    | string
    | undefined;
  if (
    updatedAt !== undefined &&
    (!/^\d{4}-\d{2}-\d{2}T/.test(updatedAt) ||
      !Number.isFinite(Date.parse(updatedAt)))
  )
    return invalid("invalid_metadata", "updated_at");
  const manifests: Manifest[] = [];
  for (let index = 0; index < record.manifests.length; index++) {
    let manifest: Manifest;
    try {
      manifest = validateManifest(record.manifests[index]);
    } catch {
      return invalid("invalid_manifest", `manifests[${index}]`);
    }
    if (manifest.app_id !== appId)
      return invalid("identity_mismatch", `manifests[${index}].app_id`);
    for (const field of ["description", "icon", "appVersion"] as const) {
      if (manifest[field] !== undefined && typeof manifest[field] !== "string")
        return invalid("invalid_metadata", `manifests[${index}].${field}`);
    }
    manifests.push(manifest);
  }
  let manifestHash: string;
  try {
    manifestHash = hashApplicationManifests(manifests);
  } catch {
    return invalid("invalid_shape", "manifests");
  }
  const suppliedHash = record.manifest_hash ?? record.manifestHash;
  if (suppliedHash !== undefined && suppliedHash !== manifestHash)
    return invalid("hash_mismatch", "manifest_hash");
  return ok({
    appId,
    manifests,
    updatedAt,
    name: (record.name as string | undefined) ?? manifests[0]!.name,
    description:
      (record.description as string | undefined) ?? manifests[0]!.description,
    manifestHash,
  });
}

/** The registry's existing FNV-1a hash over sorted JSON, shared by readers and writers. */
export function hashApplicationManifests(value: unknown): string {
  const input = stableJson(value);
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= BigInt(input.charCodeAt(index));
    hash = BigInt.asUintN(64, hash * prime);
  }
  return hash.toString(16).padStart(16, "0");
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`)
    .join(",")}}`;
}
