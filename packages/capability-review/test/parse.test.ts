import { describe, it, expect } from "bun:test";
import {
  parseCapabilityReview,
  assertBaselineSubset,
  restrictModel,
  defaultSelection,
  raiseSeverityFromMetadata,
  applyMetadataLabels,
} from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import type { SignerInfo } from "../src/index.js";
import {
  BOOTSTRAP_KV_SQL_CAPABILITIES,
  CHAT_APP_REQUEST,
  CYCLE_HEALTH_REQUEST,
  ENCRYPTION_DECRYPT_REQUEST,
  FEED_APP_REQUEST,
  FIXTURE_META,
  LISTEN_CROSS_APP_REQUEST,
  MALFORMED_SIWE,
  ORDINARY_SIWE,
  PLAIN_TEXT_MESSAGE,
  REAL_RECAP_BOOTSTRAP,
  REAL_RECAP_MIXED_A,
  REAL_RECAP_MIXED_B,
  REAL_RECAP_WITH_PATH,
  SECRETS_MUTATION_REQUEST,
  SECRETS_READ_REQUEST,
  UNKNOWN_SERVICE_REQUEST,
} from "./fixtures/index.js";

const signer: SignerInfo = {
  label: "Test signer",
  address: FIXTURE_META.address,
  chainId: FIXTURE_META.chainId,
  provenance: "managed",
};

function ctx(overrides: Partial<ParseContext> = {}): ParseContext {
  return {
    message: BOOTSTRAP_KV_SQL_CAPABILITIES,
    signer,
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "cli.tinycloud.xyz",
      verifiedOrigin: "https://cli.tinycloud.xyz",
      manifestId: null,
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    ...overrides,
  };
}

describe("parseCapabilityReview", () => {
  it("classifies TinyCloud bootstrap KV/SQL/capabilities", () => {
    const model = parseCapabilityReview(ctx());
    expect(model.protocol).toBe("tinycloud-siwe-recap");
    const families = model.permissions.map((p) => p.family).sort();
    expect(families).toContain("bootstrap-kv");
    expect(families).toContain("bootstrap-sql");
    expect(families).toContain("bootstrap-capabilities");
  });

  it("elevates a mutation to attention severity for KV", () => {
    const model = parseCapabilityReview(ctx());
    const kv = model.permissions.find((p) => p.family === "bootstrap-kv");
    expect(kv?.severity).toBe("attention");
  });

  it("keeps capabilities/read severity as standard", () => {
    const model = parseCapabilityReview(ctx());
    const cap = model.permissions.find(
      (p) => p.family === "bootstrap-capabilities",
    );
    expect(cap?.severity).toBe("standard");
  });

  it("marks capabilities/read as required and non-editable", () => {
    const model = parseCapabilityReview(ctx());
    const cap = model.permissions.find(
      (p) => p.family === "bootstrap-capabilities",
    );
    const readAction = cap?.actions.find((a) => a.ability.endsWith("/read"));
    expect(readAction?.required).toBe(true);
    expect(readAction?.editable).toBe(false);
  });

  it("classifies Chat as own-app bootstrap-kv when owner matches", () => {
    const model = parseCapabilityReview(ctx({ message: CHAT_APP_REQUEST }));
    const kv = model.permissions.find((p) => p.family === "bootstrap-kv");
    expect(kv?.ownedBySelf).toBe(true);
  });

  it("classifies Feed as own-app when owner matches", () => {
    const model = parseCapabilityReview(ctx({ message: FEED_APP_REQUEST }));
    const kv = model.permissions.find((p) => p.family === "bootstrap-kv");
    expect(kv?.ownedBySelf).toBe(true);
  });

  it("marks Listen cross-app grants as ownedBySelf=false", () => {
    const model = parseCapabilityReview(
      ctx({ message: LISTEN_CROSS_APP_REQUEST }),
    );
    const kv = model.permissions.find((p) => p.family === "bootstrap-kv");
    expect(kv?.ownedBySelf).toBe(false);
    expect(kv?.owner).toBe(FIXTURE_META.crossAppOwner.toLowerCase());
  });

  it("splits secret read vs mutation classification", () => {
    const readOnly = parseCapabilityReview(
      ctx({ message: SECRETS_READ_REQUEST }),
    );
    const readGrant = readOnly.permissions.find(
      (p) => p.family === "secret-read",
    );
    expect(readGrant?.severity).toBe("attention");

    const mutable = parseCapabilityReview(
      ctx({ message: SECRETS_MUTATION_REQUEST }),
    );
    const mutateGrant = mutable.permissions.find(
      (p) => p.family === "secret-mutation",
    );
    expect(mutateGrant?.severity).toBe("sensitive");
  });

  it("classifies encryption/decrypt as sensitive", () => {
    const model = parseCapabilityReview(
      ctx({ message: ENCRYPTION_DECRYPT_REQUEST }),
    );
    const dec = model.permissions.find(
      (p) => p.family === "encryption-decrypt",
    );
    expect(dec?.severity).toBe("sensitive");
  });

  it("classifies unknown services as unknown/attention or above", () => {
    const model = parseCapabilityReview(
      ctx({ message: UNKNOWN_SERVICE_REQUEST }),
    );
    const unk = model.permissions.find((p) => p.family === "unknown");
    expect(unk).toBeTruthy();
    expect(["attention", "sensitive"]).toContain(unk!.severity);
  });

  it("returns siwe-plain when no ReCap resources are present", () => {
    const model = parseCapabilityReview(ctx({ message: ORDINARY_SIWE }));
    expect(model.protocol).toBe("siwe-plain");
    expect(model.permissions).toHaveLength(0);
    expect(model.parseWarnings.some((w) => w.code === "no-recap")).toBe(true);
  });

  it("returns legacy-message for arbitrary text", () => {
    const model = parseCapabilityReview(ctx({ message: PLAIN_TEXT_MESSAGE }));
    expect(model.protocol).toBe("legacy-message");
    expect(model.rawMessage).toBe(PLAIN_TEXT_MESSAGE);
  });

  it("handles malformed SIWE without throwing", () => {
    const model = parseCapabilityReview(ctx({ message: MALFORMED_SIWE }));
    // Malformed input falls back to legacy-message (byte-exact) so it can
    // still be reviewed and refused rather than crashing the widget.
    expect(model.protocol).toBe("legacy-message");
  });

  it("cycle health request keeps structural severity, cannot be lowered", () => {
    const base = parseCapabilityReview(ctx({ message: CYCLE_HEALTH_REQUEST }));
    // Unverified metadata cannot raise or override severity.
    const raised = raiseSeverityFromMetadata(base, {
      [base.permissions[0]!.id]: "sensitive",
    });
    // Both attempts should be no-ops because metadataTrust is not verified.
    expect(raised.permissions[0]!.severity).toBe(base.permissions[0]!.severity);
    const labelled = applyMetadataLabels(base, {
      [base.permissions[0]!.id]: "Menstrual cycle history",
    });
    expect(labelled.permissions[0]!.metadataLabel).toBe(null);
  });

  it("decodes a real urn:recap: base64 payload into grants", () => {
    const model = parseCapabilityReview(ctx({ message: REAL_RECAP_BOOTSTRAP }));
    expect(model.protocol).toBe("tinycloud-siwe-recap");
    const families = model.permissions.map((p) => p.family).sort();
    expect(families).toContain("bootstrap-kv");
    expect(families).toContain("bootstrap-sql");
    expect(families).toContain("bootstrap-capabilities");
    // No 'unrecognized-recap-namespace' warning: the payload was decoded.
    expect(
      model.parseWarnings.some(
        (w) => w.code === "unrecognized-recap-namespace",
      ),
    ).toBe(false);
    // Each ability is preserved in its fully-qualified form so the wire
    // subset check has an exact string to match against.
    const kv = model.permissions.find((p) => p.family === "bootstrap-kv");
    expect(kv?.actions.map((a) => a.ability).sort()).toEqual([
      "tinycloud.kv/del",
      "tinycloud.kv/get",
      "tinycloud.kv/put",
    ]);
  });

  it("splits resource URI path from space for path-scoped recap entries", () => {
    const model = parseCapabilityReview(
      ctx({ message: REAL_RECAP_WITH_PATH }),
    );
    expect(model.protocol).toBe("tinycloud-siwe-recap");
    const kv = model.permissions.find((p) => p.family === "bootstrap-kv");
    // The space stays the pkh URI without the trailing path segments; the
    // path portion moves into `path`.
    expect(kv?.space).toBe(FIXTURE_META.ownSpace);
    expect(kv?.path).toBe("sql/xyz.tinycloud.listen/conversations");
  });

  it("produces identical model JSON regardless of att key ordering", () => {
    const a = parseCapabilityReview(ctx({ message: REAL_RECAP_MIXED_A }));
    const b = parseCapabilityReview(ctx({ message: REAL_RECAP_MIXED_B }));
    // rawMessage differs (different SIWE bytes) but the permissions model
    // must be identical after determinism sorting.
    expect(JSON.stringify(a.permissions)).toBe(
      JSON.stringify(b.permissions),
    );
  });
});

describe("subset validation", () => {
  it("passes an identical model", () => {
    const base = parseCapabilityReview(ctx());
    const cand = parseCapabilityReview(ctx());
    const check = assertBaselineSubset(base, cand);
    expect(check.ok).toBe(true);
  });

  it("rejects added actions", () => {
    const base = parseCapabilityReview(ctx({ message: CHAT_APP_REQUEST }));
    const broader = parseCapabilityReview(ctx()); // more capabilities
    const check = assertBaselineSubset(base, broader);
    expect(check.ok).toBe(false);
    expect(check.violations.some((v) => v.code === "added-action" || v.code === "added-space")).toBe(true);
  });

  it("rejects an altered immutable field", () => {
    const base = parseCapabilityReview(ctx());
    const cand = parseCapabilityReview(ctx());
    cand.immutable!.nonce = "tampered";
    const check = assertBaselineSubset(base, cand);
    expect(check.ok).toBe(false);
    expect(
      check.violations.some((v) => v.code === "changed-immutable-field"),
    ).toBe(true);
  });

  it("rejects a removed required action", () => {
    const base = parseCapabilityReview(ctx());
    // Restrict to only capabilities-less selection — required actions must
    // remain even if the widget maliciously omits them.
    const sel = defaultSelection(base);
    for (const grant of base.permissions) {
      for (const action of grant.actions) {
        if (action.required) sel.delete(action.id);
      }
    }
    const restricted = restrictModel({ baseline: base, selectedActionIds: sel });
    // Because restrictModel always keeps required actions, the check should
    // still pass — proving fail-closed behaviour.
    const check = assertBaselineSubset(base, restricted);
    expect(check.ok).toBe(true);
  });
});
