import type { CapabilityGrant, PermissionSeverity } from "./model.js";

// Signed resource catalog from js-sdk b7ba5e8cc9facc90a1644e3c153b1856ef1bb2cb, packages/courier/src/keys.ts. Details: TC-2905
export const COURIER_HEADING = "Courier: send and receive messages with other agents";

export const COURIER_CATALOG = [
  { path: "xyz.tinycloud.courier/me/", service: "tinycloud.kv", verbs: ["get", "list"], severity: "sensitive", text: "See all your Courier data, including your requests and approvals" },
  { path: "xyz.tinycloud.courier/to/", service: "tinycloud.kv", verbs: ["get", "put", "list", "del", "metadata"], severity: "sensitive", text: "Send messages, tasks and files to other agents, and see or delete what it sent" },
  { path: "xyz.tinycloud.courier/me/peers/", service: "tinycloud.kv", verbs: ["get", "put", "list", "del"], severity: "sensitive", text: "See, add and remove the agents you're paired with" },
  { path: "xyz.tinycloud.courier/me/mirror/", service: "tinycloud.kv", verbs: ["get", "put", "list", "del"], severity: "sensitive", exactText: "See, save and delete copies of the messages and tasks you receive", text: "See and save copies of the messages and tasks you receive" },
  { path: "xyz.tinycloud.courier/me/requests/", service: "tinycloud.kv", verbs: ["put"], severity: "standard", text: "Ask you to approve actions" },
  { path: "xyz.tinycloud.courier/me/consumed/", service: "tinycloud.kv", verbs: ["get", "put", "list"], severity: "attention", text: "See and record which of your approvals have been used" },
  { path: "xyz.tinycloud.courier/me/state/", service: "tinycloud.kv", verbs: ["get", "put", "list", "del"], severity: "attention", exactText: "Keep track of each conversation, and clear what it tracked: what it has read and which ones are paused", text: "Keep track of each conversation: what it has read and which ones are paused" },
  { path: "kv/xyz.tinycloud.courier/", service: "tinycloud.hooks", verbs: ["subscribe"], severity: "attention", text: "Get notified when your Courier data changes" },
] satisfies Array<{ path: string; service: string; verbs: string[]; severity: PermissionSeverity; text: string; exactText?: string }>;

export function courierEntry(entry: { service: string; space: string; path: string; actions: readonly string[]; serviceMismatch?: boolean }) {
  if (entry.serviceMismatch || !/^tinycloud:pkh:eip155:[0-9]+:0x[a-fA-F0-9]{40}:agents$/.test(entry.space) || entry.actions.length === 0) return null;
  return COURIER_CATALOG.find(row => row.service === entry.service && row.path === entry.path && entry.actions.every(action => row.verbs.some(verb => action === `${row.service}/${verb}`))) ?? null;
}

export function courierGrantEntry(grant: CapabilityGrant) {
  return grant.family === "courier" && grant.ownedBySelf === true
    ? courierEntry({ ...grant, actions: grant.actions.map(action => action.ability) }) : null;
}

export function courierTexts(grant: CapabilityGrant): string[] | null {
  const row = courierGrantEntry(grant);
  if (!row) return null;
  const verbs = new Set(grant.actions.map(action => action.verb));
  if (row.path === "xyz.tinycloud.courier/me/mirror/") {
    const readWrite = ["get", "put", "list"];
    if (readWrite.every(verb => verbs.has(verb)) || (verbs.size === 1 && verbs.has("del"))) {
      return [...(readWrite.every(verb => verbs.has(verb)) ? [row.text] : []), ...(verbs.has("del") ? ["Delete those saved copies"] : [])];
    }
    return null;
  }
  return row.verbs.every(verb => verbs.has(verb)) ? [row.text] : null;
}
