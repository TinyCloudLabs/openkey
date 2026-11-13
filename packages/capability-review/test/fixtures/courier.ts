import { makeRecapResource, siweWithResources, FIXTURE_META } from "./index.js";

// Producer: js-sdk b7ba5e8cc9facc90a1644e3c153b1856ef1bb2cb, packages/courier/src/keys.ts. Details: TC-2905
export const courierTuples = [
  ["tinycloud.kv", "xyz.tinycloud.courier/to/", ["get", "put", "list", "del", "metadata"]],
  ["tinycloud.kv", "xyz.tinycloud.courier/me/requests/", ["put"]],
  ["tinycloud.kv", "xyz.tinycloud.courier/me/mirror/", ["get", "put", "list", "del"]],
  ["tinycloud.kv", "xyz.tinycloud.courier/me/state/", ["get", "put", "list", "del"]],
  ["tinycloud.kv", "xyz.tinycloud.courier/me/consumed/", ["get", "put", "list"]],
  ["tinycloud.kv", "xyz.tinycloud.courier/me/peers/", ["get", "put", "list", "del"]],
  ["tinycloud.kv", "xyz.tinycloud.courier/me/", ["get", "list"]],
  ["tinycloud.hooks", "kv/xyz.tinycloud.courier/", ["subscribe"]],
] as const;
export const courierSpace = `tinycloud:pkh:eip155:1:${FIXTURE_META.address}:agents`;
export function courierMessage(tuples: readonly (readonly [string, string, readonly string[]])[] = courierTuples, space = courierSpace): string {
  const att: Record<string, Record<string, unknown[]>> = {};
  for (const [service, path, verbs] of tuples) att[`${space}/${service.replace("tinycloud.", "")}/${path}`] = Object.fromEntries(verbs.map(verb => [`${service}/${verb}`, []]));
  return siweWithResources([makeRecapResource(att)]);
}
export function courierContext(message = courierMessage()) {
  return {
    message, signer: { label: "Test signer", address: FIXTURE_META.address, chainId: 1, provenance: "managed" as const },
    editable: true, metadataTrust: { status: "unsigned" as const, reason: "no manifest" },
    reason: { text: "", source: "none" as const },
    requester: { displayName: "cli.tinycloud.xyz", verifiedOrigin: null, appId: null, manifestName: null,
      manifestNameProvenance: "none" as const, manifestId: null, manifestIdProvenance: "none" as const,
      manifestDigest: null, domainWarning: false, originWarning: false },
  };
}
