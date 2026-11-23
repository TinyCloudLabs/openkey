// A command-line tool that asks for ONE exact app key (`apps/<appId>/<key>`) on the owner's own `default` network.
//
// The request names the key as `appKey: { appId, key }` (`key` relative to `apps/<appId>/`). The screen never
// trusts that claim for what it shows: it shows the key the signed message names, and only when the two agree.
// The app host is the app id reversed label by label, and only an id that IS a reversed host names a host.

import { TICKET_APP_KEY_COPY } from "./ticket-app-key-copy.js";
import { APPS_SEGMENT, KEY_RESOURCE_PREFIX, appIdValid, isAppsKeyResource, isKeyPath, parseKeyResource } from "./key-resource.js";
import type { CapabilityReviewModel } from "./model.js";
import { decodeBase64Url } from "./parse.js";
import { parseSiweFields, serializeSiwe, type SiweFields } from "./siwe-fields.js";

/** What the tool asks for. */
export interface TicketAppKey {
  appId: string;
  /** Relative to `apps/<appId>/`. */
  key: string;
}

/** What the owner is shown. */
export interface TicketAppKeyReview {
  appId: string;
  /** `share.tinycloud.xyz` for `xyz.tinycloud.share`. */
  host: string;
  keyPath: string;
  /** The last segment of the key. */
  keyName: string;
}

const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4 = /^\d+\.\d+\.\d+\.\d+$/;
const CREATE = "tinycloud.encryption/key.create";
const DECRYPT = "tinycloud.encryption/decrypt";
const RECAP_PREFIX = "urn:recap:";
export const TICKET_APP_KEY_MAX_MS = 7 * 24 * 60 * 60 * 1000;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// JSON.parse has already validated the syntax. Scan object member names as
// written so duplicates cannot disappear before we inspect the attenuation.
function hasDuplicateJsonKeys(json: string): boolean {
  const objects: Array<Set<string> | null> = [];
  let expectKey = false;
  let i = 0;
  while (i < json.length) {
    const ch = json[i]!;
    if (ch === '"') {
      let end = i + 1;
      while (json[end] !== '"') end += json[end] === '\\' ? 2 : 1;
      const keys = objects[objects.length - 1];
      if (keys && expectKey) {
        const key = JSON.parse(json.slice(i, end + 1)) as string;
        if (keys.has(key)) return true;
        keys.add(key);
        expectKey = false;
      }
      i = end + 1;
      continue;
    }
    if (ch === '{') {
      objects.push(new Set());
      expectKey = true;
    } else if (ch === '[') {
      objects.push(null);
      expectKey = false;
    } else if (ch === '}' || ch === ']') {
      objects.pop();
      expectKey = false;
    } else if (ch === ',') {
      expectKey = objects[objects.length - 1] instanceof Set;
    }
    i += 1;
  }
  return false;
}

function attenuation(resource: string, strict = false): Record<string, unknown> | null {
  if (!resource.startsWith(RECAP_PREFIX)) return null;
  const json = decodeBase64Url(resource.slice(RECAP_PREFIX.length), strict);
  if (json === null) return null;
  try {
    const recap: unknown = JSON.parse(json);
    if (strict && hasDuplicateJsonKeys(json)) return null;
    return record(recap) && record(recap.att) ? recap.att : null;
  } catch {
    return null;
  }
}

function noCaveats(value: unknown): boolean {
  return Array.isArray(value) && (value.length === 0 ||
    (value.length === 1 && record(value[0]) && Object.keys(value[0]).length === 0));
}

/** Check the as-written SIWE before the web claims a command-line handoff. */
export function validTicketAppKeyRequest(fields: SiweFields, appKey: TicketAppKey | undefined, now: number): boolean {
  if (!appKey) {
    return !(fields.resources ?? []).some((resource) =>
      Object.keys(attenuation(resource) ?? {}).some(isAppsKeyResource),
    );
  }
  if (fields.resources?.length !== 1) return false;
  const att = attenuation(fields.resources[0]!, true);
  if (!att || Object.keys(att).length !== 1) return false;
  const resource = ticketAppKeyResource(fields, appKey);
  const abilities = att[resource];
  if (!record(abilities) || Object.keys(abilities).length !== 2 ||
      !noCaveats(abilities[DECRYPT]) || !noCaveats(abilities[CREATE])) return false;
  const end = Date.parse(fields.expirationTime ?? "");
  return end > now && end <= now + TICKET_APP_KEY_MAX_MS;
}

function ticketAppKeyResource(fields: SiweFields, appKey: TicketAppKey): string {
  return `${KEY_RESOURCE_PREFIX}did:pkh:eip155:${fields.chainId}:${fields.address}:default/${ticketAppKeyPath(appKey)}`;
}

/** Check the server admitted the reviewed grant and read its default end. */
export function admittedTicketAppKeyDefault(
  reply: unknown, appKey: TicketAppKey, original: string, now: number, defaultWindowMs: number,
): string | null {
  const parsed = parseSiweFields(original);
  if (!parsed.ok || !parsed.fields.expirationTime || !record(reply) ||
      reply.appId !== appKey.appId || reply.host !== appHostForAppId(appKey.appId) || reply.key !== appKey.key ||
      reply.resource !== ticketAppKeyResource(parsed.fields, appKey) ||
      !Array.isArray(reply.abilities) || reply.abilities.length !== 2 ||
      !reply.abilities.includes("decrypt") || !reply.abilities.includes("key.create") ||
      typeof reply.requestedExpiresAt !== "string" || typeof reply.maxExpiresAt !== "string" ||
      typeof reply.defaultExpiresAt !== "string") return null;

  const ceiling = Date.parse(parsed.fields.expirationTime);
  const end = Date.parse(reply.defaultExpiresAt);
  // The HTTP Date header has whole-second precision.
  const defaultCeiling = now + defaultWindowMs + 999;
  if (Date.parse(reply.requestedExpiresAt) !== ceiling || Date.parse(reply.maxExpiresAt) !== ceiling ||
      !(end > now && end <= ceiling && end <= defaultCeiling)) return null;
  return new Date(end).toISOString();
}

/** The sealed candidate may differ from the reviewed message only at the accepted expiry field. */
export function matchesTicketAppKeyPreview(original: string, candidate: string, acceptedEnd: string, now: number): boolean {
  const parsed = parseSiweFields(original);
  if (!parsed.ok || !parsed.fields.expirationTime) return false;
  const acceptedMs = Date.parse(acceptedEnd);
  return acceptedMs > now &&
    acceptedMs <= now + TICKET_APP_KEY_MAX_MS &&
    acceptedMs <= Date.parse(parsed.fields.expirationTime) &&
    candidate === serializeSiwe({ ...parsed.fields, expirationTime: acceptedEnd });
}

/** The host an app id names, or `null` when the id is not a reversed host of two or more labels. */
export function appHostForAppId(appId: string): string | null {
  if (!appIdValid(appId) || IPV4.test(appId)) return null;
  const labels = appId.split(".");
  if (labels.length < 2 || labels[0] === "localhost") return null;
  if (!labels.every((label) => DOMAIN_LABEL.test(label))) return null;
  return labels.reverse().join(".");
}

/** The `appKey` of a request, read strictly: two text fields and no others; null for anything else. */
export function readTicketAppKey(value: unknown): TicketAppKey | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const names = Object.keys(record);
  if (names.length !== 2 || !names.includes("appId") || !names.includes("key")) return null;
  const { appId, key } = record;
  if (typeof appId !== "string" || typeof key !== "string") return null;
  const prefix = `${APPS_SEGMENT}/${appId}/`;
  return appHostForAppId(appId) !== null && !key.startsWith(prefix) && isKeyPath(prefix + key) ? { appId, key } : null;
}

/** `apps/<appId>/<key>`. */
export function ticketAppKeyPath(appKey: TicketAppKey): string {
  return `${APPS_SEGMENT}/${appKey.appId}/${appKey.key}`;
}

/**
 * The review of a request that carries `appKey`, or `null` when the request is not exactly that: the signed message
 * must hold ONE grant, on the signer's own `default` network, on the key the request names, with the abilities
 * `decrypt` and `key.create` and no others. `null` means the screen must not approve it.
 */
export function reviewTicketAppKey(model: CapabilityReviewModel, appKey: TicketAppKey): TicketAppKeyReview | null {
  const host = appHostForAppId(appKey.appId);
  if (host === null || model.permissions.length !== 1) return null;
  const grant = model.permissions[0]!;
  if (grant.family !== "app-keys" || grant.ownedBySelf !== true) return null;
  const parsed = parseKeyResource(grant.path === "" ? grant.space : `${grant.space}/${grant.path}`);
  const keyPath = ticketAppKeyPath(appKey);
  if (!parsed || parsed.isPrefix || parsed.network !== "default" || parsed.keyPath !== keyPath) return null;
  const abilities = grant.actions.map((action) => action.ability);
  if (abilities.length !== 2 || !abilities.includes(CREATE) || !abilities.includes(DECRYPT) ||
      !grant.actions.every((action) => noCaveats(action.caveats))) return null;
  return { appId: appKey.appId, host, keyPath, keyName: keyPath.slice(keyPath.lastIndexOf("/") + 1) };
}

/** Fill `{host}`, `{keyName}` and `{keyPath}` in one of the `TICKET_APP_KEY_COPY` texts. */
export function ticketAppKeyText(template: string, review: TicketAppKeyReview): string {
  return template.replace(/\{(host|keyName|keyPath)\}/g, (_match, name: "host" | "keyName" | "keyPath") => review[name]);
}

export type TicketAppKeyRefusal = keyof typeof TICKET_APP_KEY_COPY.refusals;

const REFUSALS: Readonly<Record<string, TicketAppKeyRefusal | Readonly<Record<string, TicketAppKeyRefusal>>>> = {
  app_keys_file_missing: "missing",
  app_keys_file_invalid: "invalid",
  app_key_not_listed: "notListed",
  app_keys_file_unavailable: "unavailable",
  app_key_fetch_busy: "fetchBusy",
  app_key_request_invalid: {
    request_invalid: "request_invalid",
    ticket_required: "ticket_required",
    app_id: "app_id",
    recap: "recap",
    account: "account",
    expiry: "expiry",
  },
};

/** Match the API's structured refusal to the owner's copy. */
export function ticketAppKeyRefusal(code: unknown, reason?: unknown): TicketAppKeyRefusal | null {
  if (typeof code !== "string" || !Object.hasOwn(REFUSALS, code)) return null;
  const refusal = REFUSALS[code]!;
  if (typeof refusal === "string") return refusal;
  return typeof reason === "string" && Object.hasOwn(refusal, reason) ? refusal[reason]! : "request_invalid";
}

/** The owner's line for a refusal. */
export function ticketAppKeyRefusalText(refusal: TicketAppKeyRefusal, review: TicketAppKeyReview): string {
  return ticketAppKeyText(TICKET_APP_KEY_COPY.refusals[refusal], review);
}
