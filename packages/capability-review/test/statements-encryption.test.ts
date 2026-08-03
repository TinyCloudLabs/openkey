// Sol MAJOR-3: production encryption ability is `network.create`, not
// bare `create`. `verbOf('tinycloud.encryption/network.create')` returns
// `network.create`, so the CREATE_VERBS set MUST recognize that compound
// verb — otherwise the combined create+decrypt path never fires and the
// widget silently degrades to the fallback statement for the primary
// production request shape.
//
// These tests exercise `buildStatement` directly against grants built
// with the exact abilities the js-sdk emits.

import { describe, expect, it } from "bun:test";

import {
  buildStatement,
  grantReachesSecretDataOrDecryption,
  parseCapabilityReview,
} from "../src/index.js";
import type { CapabilityGrant, SignerInfo } from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import {
  ENCRYPTION_NETWORK_CREATE_AND_DECRYPT_REQUEST,
  ENCRYPTION_NETWORK_CREATE_ONLY_REQUEST,
  FIXTURE_META,
} from "./fixtures/index.js";

const SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default`;

function encryptionGrant(abilities: string[]): CapabilityGrant {
  const path = "health-data";
  return {
    id: `tinycloud.encryption\x00${SPACE}\x00${path}`,
    family: "encryption-decrypt",
    severity: "sensitive",
    service: "tinycloud.encryption",
    space: SPACE,
    path,
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    resourceService: null,
    actions: abilities.map((ability) => ({
      id: `tinycloud.encryption\x00${SPACE}\x00${path}\x00${ability}`,
      ability,
      verb: ability.slice(ability.indexOf("/") + 1),
      required: false,
      selected: true,
      editable: true,
      caveats: [{}],
    })),
  };
}

describe("buildStatement — tinycloud.encryption/network.create", () => {
  it("network.create + decrypt in one grant selects the combined statement", () => {
    const grant = encryptionGrant([
      "tinycloud.encryption/network.create",
      "tinycloud.encryption/decrypt",
    ]);
    expect(buildStatement(grant).primaryText).toBe(
      "Set up encrypted data access and decrypt protected data",
    );
  });

  it("network.create alone selects 'Set up encrypted data access'", () => {
    const grant = encryptionGrant(["tinycloud.encryption/network.create"]);
    expect(buildStatement(grant).primaryText).toBe(
      "Set up encrypted data access",
    );
    expect(grantReachesSecretDataOrDecryption(grant)).toBe(false);
  });

  it("decrypt alone still selects 'Decrypt protected data'", () => {
    const grant = encryptionGrant(["tinycloud.encryption/decrypt"]);
    expect(buildStatement(grant).primaryText).toBe("Decrypt protected data");
    expect(grantReachesSecretDataOrDecryption(grant)).toBe(true);
  });
});

// Also exercise the full parser pipeline against SIWE ReCap fixtures so
// we know the classifier reaches the same statement for real messages.

const signer: SignerInfo = {
  label: "Test signer",
  address: FIXTURE_META.address,
  chainId: FIXTURE_META.chainId,
  provenance: "managed",
};

function ctx(message: string): ParseContext {
  return {
    message,
    signer,
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "cli.tinycloud.xyz",
      verifiedOrigin: "https://cli.tinycloud.xyz",
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  };
}

describe("parseCapabilityReview — encryption network.create", () => {
  it("network.create + decrypt produces the combined statement", () => {
    const model = parseCapabilityReview(
      ctx(ENCRYPTION_NETWORK_CREATE_AND_DECRYPT_REQUEST),
    );
    const enc = model.permissions.find(
      (p) => p.service === "tinycloud.encryption",
    );
    expect(enc).toBeTruthy();
    const stmt = buildStatement(enc!);
    expect(stmt.primaryText).toBe(
      "Set up encrypted data access and decrypt protected data",
    );
  });

  it("network.create only produces the create-only statement", () => {
    const model = parseCapabilityReview(
      ctx(ENCRYPTION_NETWORK_CREATE_ONLY_REQUEST),
    );
    const enc = model.permissions.find(
      (p) => p.service === "tinycloud.encryption",
    );
    expect(enc).toBeTruthy();
    const stmt = buildStatement(enc!);
    expect(stmt.primaryText).toBe("Set up encrypted data access");
  });
});
