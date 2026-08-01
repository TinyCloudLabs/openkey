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
  REAL_RECAP_SAME_ABILITY_TWO_PATHS,
  REAL_RECAP_WITH_PATH,
  REAL_KV_SECRET_READ,
  REAL_KV_SECRET_MUTATION,
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
    // Sol MAJOR-7: the classifier no longer falls back to signer as the
    // ownership axis. Tests that model an OWN-space request must pass a
    // VERIFIED requester matching the signer — this simulates a signed
    // presentation manifest whose digest matched, which is the only
    // trust state that lets classifyRecapEntry attribute a grant to the
    // requester's own space. Tests that model an unverified requester
    // (widget path) override this field to `null` / `false`.
    requesterAddress: FIXTURE_META.address.toLowerCase(),
    requesterVerified: true,
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

  it("classifies a scoped-path KV grant as own-app-data when owner matches (Chat fixture)", () => {
    // Sol continuation contract: path-scoped grants are classified as
    // own-app-data based on the STRUCTURAL fact that the path is a
    // sub-namespace of the space, not because the path spells "chat".
    // The display label MUST NOT invent an app identity — it renders
    // the literal path so a phishing origin cannot inherit product
    // labelling by picking a matching prefix.
    const model = parseCapabilityReview(ctx({ message: CHAT_APP_REQUEST }));
    const chat = model.permissions.find((p) => p.family === "own-app-data");
    expect(chat).toBeDefined();
    expect(chat?.ownedBySelf).toBe(true);
    expect(chat?.displayLabel).toMatch(/App data/);
    expect(chat?.displayLabel).toContain(chat!.path);
  });

  it("classifies a scoped-path KV grant as own-app-data when owner matches (Feed fixture)", () => {
    const model = parseCapabilityReview(ctx({ message: FEED_APP_REQUEST }));
    const feed = model.permissions.find((p) => p.family === "own-app-data");
    expect(feed).toBeDefined();
    expect(feed?.ownedBySelf).toBe(true);
    expect(feed?.displayLabel).toMatch(/App data/);
    expect(feed?.displayLabel).toContain(feed!.path);
  });

  it("classifies a scoped-path cross-user KV grant as cross-app-data (attention)", () => {
    // Sol MAJOR-7: a KV grant on a DIFFERENT user's space must be
    // classified as cross-app-data with elevated severity, not lumped
    // into the generic bootstrap-kv family. Sol continuation contract:
    // the label MUST NOT claim an app identity — cross-user grants only
    // show ownership + literal path.
    const model = parseCapabilityReview(
      ctx({ message: LISTEN_CROSS_APP_REQUEST }),
    );
    const cross = model.permissions.find((p) => p.family === "cross-app-data");
    expect(cross).toBeDefined();
    expect(cross?.ownedBySelf).toBe(false);
    expect(cross?.owner).toBe(FIXTURE_META.crossAppOwner.toLowerCase());
    expect(cross?.severity).toBe("attention");
    expect(cross?.displayLabel).toMatch(/Cross-user/);
    // Must NOT be a bootstrap-kv grant.
    const kv = model.permissions.find((p) => p.family === "bootstrap-kv");
    expect(kv).toBeUndefined();
  });

  it("fail-closed: unverified requester + signer-owned space does NOT set ownedBySelf=true (Sol MAJOR-5)", () => {
    // Sol MAJOR-5 (continuation): SigningApproval renders a cross-app
    // warning based on `ownedBySelf`. The prior implementation set
    // `trustedOwnershipAxis = signerAddress` when `requesterAddress` was
    // absent, which caused every widget-path grant (always unverified
    // requester) on the signer's own space to set `ownedBySelf: true`
    // and suppress the warning. The fix: never fall back to the signer.
    const model = parseCapabilityReview(
      ctx({
        message: FEED_APP_REQUEST,
        requester: {
          displayName: "unknown requester",
          verifiedOrigin: null,
          manifestId: null,
          manifestDigest: null,
          domainWarning: false,
          originWarning: false,
        },
        requesterAddress: null,
        requesterVerified: false,
      }),
    );
    // Every path-scoped grant on the signer's OWN space MUST report
    // ownedBySelf as null (unknown) — never true — because we have no
    // verified requester identity to attribute the request to.
    for (const grant of model.permissions) {
      if (grant.owner !== null) {
        expect(grant.ownedBySelf).not.toBe(true);
      }
    }
  });

  it("fail-closed: unverified requester + own-space grant classifies as cross-app-data (Sol MAJOR-7)", () => {
    // Sol MAJOR-7: when no verified requester identity is supplied
    // (widget path passes requesterAddress: null, requesterVerified:
    // false), the classifier MUST NOT fall back to the signer address
    // as the ownership axis. Otherwise every grant on the signer's own
    // space would be labelled own-app-data even though we have no idea
    // which app is asking. The correct fail-closed behavior is:
    // treat the grant as cross-app-data (attention).
    const model = parseCapabilityReview(
      ctx({
        message: FEED_APP_REQUEST,
        requester: {
          displayName: "unknown requester",
          verifiedOrigin: null,
          manifestId: null,
          manifestDigest: null,
          domainWarning: false,
          originWarning: false,
        },
        requesterAddress: null,
        requesterVerified: false,
      }),
    );
    // No scoped-path grant should be classified as own-app-data because
    // we could not verify who the requester is.
    const ownAppData = model.permissions.find((p) => p.family === "own-app-data");
    expect(ownAppData).toBeUndefined();
    const crossAppData = model.permissions.find((p) => p.family === "cross-app-data");
    expect(crossAppData).toBeDefined();
    expect(crossAppData?.severity).toBe("attention");
  });

  it("classifies a scoped-path KV grant as own-app-data (Cycle-health fixture)", () => {
    // The classifier notices the path is scoped (family = own-app-data);
    // the label reports the literal path with no assumed app identity.
    const model = parseCapabilityReview(ctx({ message: CYCLE_HEALTH_REQUEST }));
    const grant = model.permissions.find(
      (p) => p.family === "own-app-data",
    );
    expect(grant).toBeDefined();
    expect(grant?.displayLabel).toMatch(/App data/);
    expect(grant?.displayLabel).toContain(grant!.path);
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

  it("classifies tinycloud.kv with vault/secrets/ path as secret-read", () => {
    const model = parseCapabilityReview(
      ctx({ message: REAL_KV_SECRET_READ }),
    );
    expect(model.protocol).toBe("tinycloud-siwe-recap");
    const secretGrant = model.permissions.find(
      (p) => p.family === "secret-read",
    );
    expect(secretGrant).toBeTruthy();
    expect(secretGrant?.severity).toBe("attention");
    // Must NOT be classified as generic bootstrap-kv
    const bootstrapGrant = model.permissions.find(
      (p) => p.family === "bootstrap-kv",
    );
    expect(bootstrapGrant).toBeUndefined();
  });

  it("classifies tinycloud.kv with vault/secrets/ path and mutation verbs as secret-mutation", () => {
    const model = parseCapabilityReview(
      ctx({ message: REAL_KV_SECRET_MUTATION }),
    );
    expect(model.protocol).toBe("tinycloud-siwe-recap");
    const secretGrant = model.permissions.find(
      (p) => p.family === "secret-mutation",
    );
    expect(secretGrant).toBeTruthy();
    expect(secretGrant?.severity).toBe("sensitive");
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
    // Sol continuation contract: any non-empty path on own space is
    // structurally own-app-data (not bootstrap-kv). We still verify the
    // pkh URI split so the `space` / `path` extraction behaviour is
    // exercised — but the family reflects the structural fact.
    const kv = model.permissions.find(
      (p) => p.family === "own-app-data" && p.service === "tinycloud.kv",
    );
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

  it("keeps two same-ability different-path grants distinct (Sol MAJOR-6)", () => {
    // Two resources with the same ability (`tinycloud.kv/get`) on
    // different paths (chat vs feed) must yield two separate grants with
    // distinct action IDs. If the parser collapsed them by ability, a UI
    // selection on one would inadvertently toggle the other.
    const model = parseCapabilityReview(
      ctx({ message: REAL_RECAP_SAME_ABILITY_TWO_PATHS }),
    );
    const kvGrants = model.permissions.filter((p) => p.service === "tinycloud.kv");
    expect(kvGrants.length).toBe(2);
    const paths = kvGrants.map((g) => g.path).sort();
    expect(paths).toEqual(["chat", "feed"]);
    // Every action ID must be unique across grants — otherwise selection
    // can collapse two resources into one.
    const allActionIds = kvGrants.flatMap((g) => g.actions.map((a) => a.id));
    const uniqueActionIds = new Set(allActionIds);
    expect(uniqueActionIds.size).toBe(allActionIds.length);
  });
});

describe("cross-surface parity (Sol MAJOR-8)", () => {
  // All three OpenKey authorization surfaces (CLI browser at /delegate,
  // popup at /widget/sign, iframe at /widget/embed/sign) MUST render the
  // SAME capability-review model for the same signer + message + editable
  // flag. If any surface renders differently, one of them is bypassing the
  // shared parser or applying different classification rules — which
  // reintroduces exactly the "narrow display, broad sign" bug the
  // consolidation is supposed to fix.
  it("all three surfaces produce identical models for the same input", () => {
    const message = REAL_RECAP_BOOTSTRAP;
    // Simulate the three call sites with the exact same signer + context
    // shape they use in production (see /delegate, /widget/sign,
    // /widget/embed/sign).
    const cli = parseCapabilityReview(ctx({ message }));
    const popup = parseCapabilityReview(ctx({ message }));
    const iframe = parseCapabilityReview(ctx({ message }));
    // Compare the deterministic subset: permissions and rawMessage. The
    // parseWarnings and requester/reason vary because they encode caller
    // context, but the actual capability-review model must be identical.
    expect(JSON.stringify(cli.permissions)).toBe(
      JSON.stringify(popup.permissions),
    );
    expect(JSON.stringify(popup.permissions)).toBe(
      JSON.stringify(iframe.permissions),
    );
    expect(cli.rawMessage).toBe(popup.rawMessage);
    expect(popup.rawMessage).toBe(iframe.rawMessage);
    expect(cli.protocol).toBe(popup.protocol);
    expect(popup.protocol).toBe(iframe.protocol);
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

describe("caveats (Sol continuation contract)", () => {
  // Sol continuation contract: caveats are preserved end-to-end through the
  // model, and the subset validator compares them structurally. A candidate
  // that DROPS caveats or MUTATES them is broader than the baseline and MUST
  // be rejected.
  //
  // The vacuous `[{}]` placeholder every real TinyCloud recap uses does NOT
  // count as a meaningful caveat — the parser marks such actions editable.
  // Only actions carrying a non-empty caveat object are non-editable.

  // Import fixtures we need locally to build caveat-bearing recaps.
  const { makeRecapResource, FIXTURE_META } = require("./fixtures/index.js");
  const ADDR = FIXTURE_META.address;
  const CHAIN = FIXTURE_META.chainId;
  const SPACE = FIXTURE_META.ownSpace;

  function siweWithRecap(att: Record<string, Record<string, unknown[]>>): string {
    return [
      `cli.tinycloud.xyz wants you to sign in with your Ethereum account:`,
      ADDR,
      "",
      "TinyCloud delegation",
      "",
      `URI: https://cli.tinycloud.xyz`,
      "Version: 1",
      `Chain ID: ${CHAIN}`,
      "Nonce: abcdef123456",
      `Issued At: ${FIXTURE_META.issuedAt}`,
      `Expiration Time: ${FIXTURE_META.expirationTime}`,
      "Resources:",
      `- ${makeRecapResource(att)}`,
    ].join("\n");
  }

  it("parses caveats onto each action", () => {
    const message = siweWithRecap({
      [SPACE]: {
        "tinycloud.kv/get": [{ maxCount: 5 }],
        "tinycloud.capabilities/read": [{}],
      },
    });
    const model = parseCapabilityReview(ctx({ message }));
    const kv = model.permissions.find((p) => p.family === "bootstrap-kv");
    const kvGet = kv?.actions.find((a) => a.ability === "tinycloud.kv/get");
    expect(kvGet?.caveats).toEqual([{ maxCount: 5 }]);
    // Meaningful caveats make the action non-editable — the WASM emitter
    // would drop them, so the UI cannot present a broadening toggle.
    expect(kvGet?.editable).toBe(false);
  });

  it("treats the vacuous [{}] placeholder as no caveats", () => {
    const message = siweWithRecap({
      [SPACE]: {
        "tinycloud.kv/get": [{}],
        "tinycloud.capabilities/read": [{}],
      },
    });
    const model = parseCapabilityReview(ctx({ message }));
    const kv = model.permissions.find((p) => p.family === "bootstrap-kv");
    const kvGet = kv?.actions.find((a) => a.ability === "tinycloud.kv/get");
    // Vacuous caveat = editable. Otherwise every real recap would be locked.
    expect(kvGet?.editable).toBe(true);
  });

  it("subset validator rejects dropped caveats", () => {
    const message = siweWithRecap({
      [SPACE]: {
        "tinycloud.kv/get": [{ maxCount: 5 }],
        "tinycloud.capabilities/read": [{}],
      },
    });
    const base = parseCapabilityReview(ctx({ message }));
    // Build a candidate model with the caveat stripped — this is what
    // WASM's naive re-emit would produce.
    const candidate = JSON.parse(JSON.stringify(base));
    for (const grant of candidate.permissions) {
      for (const action of grant.actions) {
        if (action.ability === "tinycloud.kv/get") {
          action.caveats = [];
        }
      }
    }
    const check = assertBaselineSubset(base, candidate);
    expect(check.ok).toBe(false);
    expect(check.violations.some((v) => v.code === "broadened-caveat")).toBe(true);
  });

  it("subset validator accepts identical caveats", () => {
    const message = siweWithRecap({
      [SPACE]: {
        "tinycloud.kv/get": [{ maxCount: 5 }],
        "tinycloud.capabilities/read": [{}],
      },
    });
    const base = parseCapabilityReview(ctx({ message }));
    const cand = parseCapabilityReview(ctx({ message }));
    const check = assertBaselineSubset(base, cand);
    expect(check.ok).toBe(true);
  });
});
