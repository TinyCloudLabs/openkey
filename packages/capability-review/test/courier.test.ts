import { describe, expect, test } from "bun:test";
import { parseCapabilityReview, buildSummaryStatements } from "../src/index.js";
import { makeRecapResource, siweWithResources } from "./fixtures/index.js";
import { courierContext, courierMessage, courierSpace, courierTuples } from "./fixtures/courier.js";

describe("Courier capability review", () => {
  test("groups the full producer request and preserves its authority and unsigned provenance", () => {
    const context = courierContext();
    const model = parseCapabilityReview(context);
    expect(model.permissions).toHaveLength(8);
    expect(model.permissions.every(grant => grant.family === "courier")).toBe(true);
    expect(model.rawMessage).toBe(context.message);
    expect(model.metadataTrust.status).toBe("unsigned");
    expect(buildSummaryStatements(model.permissions)).toHaveLength(9);
    expect(model.permissions.find(grant => grant.path.endsWith("me/"))?.severity).toBe("sensitive");
    for (const [service, path, verbs] of courierTuples) {
      const grant = model.permissions.find(grant => grant.path === path)!;
      expect(grant.actions.map(action => action.ability).sort()).toEqual(verbs.map(verb => `${service}/${verb}`).sort());
    }
  });
  test("recognizes subsets without claiming omitted abilities", () => {
    for (const [service, path, verbs] of courierTuples) for (const verb of verbs) {
      const model = parseCapabilityReview(courierContext(courierMessage([[service, path, [verb]]])));
      expect(model.permissions[0]?.family).toBe("courier");
      const rows = buildSummaryStatements(model.permissions);
      if (verb !== "del") expect(rows.some(row => /Delete|delete|remove/.test(row.primaryText))).toBe(false);
    }
  });
  test("keeps other tuples visible at Sensitive", () => {
    const path = "xyz.tinycloud.courier/me/consumed/";
    const badPaths = [path + "extra", path.slice(0, -1), path.toUpperCase(), path.replace("courier", "cоurier"), path.replace("me", "%6de"), path + "../", "xyz.tinycloud.courier/", path + "*"];
    for (const candidate of badPaths) {
      const model = parseCapabilityReview(courierContext(courierMessage([["tinycloud.kv", candidate, ["get", "list", "put"]]])));
      expect(model.permissions[0]?.family).toBe("unknown");
      expect(model.permissions[0]?.severity).toBe("sensitive");
    }
    for (const actions of [["get", "list", "put", "del"], ["*"], ["decrypt"]]) {
      const model = parseCapabilityReview(courierContext(courierMessage([["tinycloud.kv", path, actions]])));
      expect(model.permissions[0]).toMatchObject({ family: "unknown", severity: "sensitive" });
    }
    const foreign = courierSpace.replace("0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222");
    expect(parseCapabilityReview(courierContext(courierMessage(undefined, foreign))).permissions.every(grant => grant.family === "unknown" && grant.severity === "sensitive")).toBe(true);
  });
  test("requires the exact signed space and matching service, independent of metadata", () => {
    for (const space of [courierSpace.replace(":agents", ":default"), courierSpace.replace(":1:", ":2:"), courierSpace + "/", "agents"]) {
      const model = parseCapabilityReview(courierContext(courierMessage(undefined, space)));
      expect(model.permissions.every(grant => grant.family !== "courier")).toBe(true);
    }
    const path = "xyz.tinycloud.courier/me/consumed/";
    const message = siweWithResources([makeRecapResource({ [`${courierSpace}/sql/${path}`]: { "tinycloud.kv/get": [], "tinycloud.kv/put": [], "tinycloud.kv/list": [] } })]);
    const model = parseCapabilityReview({ ...courierContext(message), metadataTrust: { status: "verified" as const, reason: "fixture" } });
    expect(model.permissions[0]).toMatchObject({ family: "unknown", severity: "sensitive", serviceMismatch: true });
    expect(buildSummaryStatements(model.permissions).some(row => row.primaryText.includes("See and record"))).toBe(false);
  });
  test("rejects every producer tuple with added authority", () => {
    for (const [service, path, verbs] of courierTuples) {
      const model = parseCapabilityReview(courierContext(courierMessage([[service, path, [...verbs, "*"]]])));
      expect(model.permissions[0]).toMatchObject({ family: "unknown", severity: "sensitive" });
    }
  });
  test("applies authority-specific severity floors", () => {
    const grants = parseCapabilityReview(courierContext()).permissions;
    for (const suffix of ["to/", "me/peers/", "me/mirror/", "me/"]) expect(grants.find(grant => grant.path === `xyz.tinycloud.courier/${suffix}`)?.severity).toBe("sensitive");
    for (const suffix of ["me/state/", "me/consumed/"]) expect(grants.find(grant => grant.path === `xyz.tinycloud.courier/${suffix}`)?.severity).toBe("attention");
    expect(grants.find(grant => grant.service === "tinycloud.hooks")?.severity).toBe("attention");
    expect(grants.find(grant => grant.path.endsWith("me/requests/"))?.severity).toBe("standard");
  });
  test("mixed requests retain the additional Sensitive row", () => {
    const model = parseCapabilityReview(courierContext(courierMessage([...courierTuples, ["tinycloud.kv", "xyz.tinycloud.courier/me/approvals/", ["put"]]])));
    expect(model.permissions.filter(grant => grant.family === "courier")).toHaveLength(8);
    expect(model.permissions.find(grant => grant.family === "unknown")?.severity).toBe("sensitive");
    expect(buildSummaryStatements(model.permissions).some(row => row.severity === "sensitive")).toBe(true);
  });
});
