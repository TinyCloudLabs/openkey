// A command-line tool that asks for ONE exact app key (`apps/<appId>/<key>`) on the owner's own `default` network.
//
// The request names the key as `appKey: { appId, key }` (`key` relative to `apps/<appId>/`). The screen never
// trusts that claim for what it shows: it shows the key the signed message names, and only when the two agree.
// The app host is the app id reversed label by label, and only an id that IS a reversed host names a host.

import { TICKET_APP_KEY_COPY } from "./copy.js";
import { APPS_SEGMENT, appIdValid, isKeyPath, parseKeyResource } from "./key-resource.js";
import type { CapabilityReviewModel } from "./model.js";

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
const CREATE = ["tinycloud.encryption/key.create", "encryption/key.create"];
const DECRYPT = ["tinycloud.encryption/decrypt", "encryption/decrypt"];

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
  const exact =
    abilities.length === 2 &&
    abilities.some((ability) => CREATE.includes(ability)) &&
    abilities.some((ability) => DECRYPT.includes(ability));
  if (!exact) return null;
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
