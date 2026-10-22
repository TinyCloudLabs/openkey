// TC-1456 S5 consent copy for held credential presentation (DESIGN-v5 §3.3b).
//
// A `tinycloud.credentials/present` grant is classified into its own family.
// Its copy names the verified request origin in full, never the manifest name
// or the SIWE domain, and falls back to a generic phrase when no origin was
// verified. Only `present` on the credentials service earns the family.

import { describe, expect, it } from "bun:test";

import {
  buildStatement,
  classifyRecapEntry,
  classifySeverityFromActions,
  parseCapabilityReview,
  type CapabilityGrant,
} from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import { makeRecapResource } from "./fixtures/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const SPACE = `tinycloud:pkh:eip155:1:${ACCOUNT}:default`;
const CREDENTIALS_RESOURCE = `${SPACE}/credentials`;
const EXPIRES = "2026-08-07T00:00:00.000Z";
const VERIFIED_ORIGIN = "https://share.tinycloud.xyz";
const SIWE_DOMAIN = "cli.tinycloud.xyz";
const MANIFEST_NAME = "Share Manifest Name";

function siweWithRecap(recap: string, expiration: string = EXPIRES): string {
  return [
    `${SIWE_DOMAIN} wants you to sign in with your Ethereum account:`,
    ACCOUNT,
    "",
    "TinyCloud delegation",
    "",
    `URI: https://${SIWE_DOMAIN}`,
    "Version: 1",
    "Chain ID: 1",
    "Nonce: abcdef123456",
    "Issued At: 2026-07-31T00:00:00.000Z",
    `Expiration Time: ${expiration}`,
    "Resources:",
    `- ${recap}`,
  ].join("\n");
}

function presentRecap(abilities: string[]): string {
  return makeRecapResource({
    [CREDENTIALS_RESOURCE]: Object.fromEntries(
      abilities.map((ability) => [ability, [{}]]),
    ),
  });
}

const PRESENT_MESSAGE = siweWithRecap(
  presentRecap(["tinycloud.credentials/present"]),
);

function parseContext(
  message: string,
  requester: Partial<ParseContext["requester"]> = {},
): ParseContext {
  return {
    message,
    signer: {
      label: "Test signer",
      address: ACCOUNT,
      chainId: 1,
      provenance: "managed",
    },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: SIWE_DOMAIN,
      verifiedOrigin: VERIFIED_ORIGIN,
      appId: null,
      manifestName: MANIFEST_NAME,
      manifestNameProvenance: "manifest",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
      ...requester,
    },
  };
}

function presentGrant(): CapabilityGrant {
  const model = parseCapabilityReview(parseContext(PRESENT_MESSAGE));
  const grant = model.permissions.find(
    (p) => p.family === "held-credential-present",
  );
  if (!grant) throw new Error("expected a held-credential-present grant");
  return grant;
}

describe("classify: held credential presentation family", () => {
  const entry = (actions: string[], serviceMismatch?: boolean) => ({
    service: "tinycloud.credentials",
    space: SPACE,
    path: "credentials",
    actions,
    signerAddress: ACCOUNT,
    serviceMismatch,
  });

  it("classifies present on the credentials service into its own family", () => {
    const result = classifyRecapEntry(
      entry(["tinycloud.credentials/present"]),
    );
    expect(result.family).toBe("held-credential-present");
  });

  it("rates a held presentation sensitive", () => {
    expect(
      classifySeverityFromActions("held-credential-present", [
        "tinycloud.credentials/present",
      ]),
    ).toBe("sensitive");
  });

  it("does not grant the family when any action is not present", () => {
    const result = classifyRecapEntry(
      entry(["tinycloud.credentials/present", "tinycloud.credentials/get"]),
    );
    expect(result.family).toBe("unknown");
  });

  it("does not grant the family to a service-mismatched entry", () => {
    const result = classifyRecapEntry(
      entry(["tinycloud.credentials/present"], true),
    );
    expect(result.family).toBe("unknown");
  });
});

describe("statement: held credential presentation copy", () => {
  it("names the verified origin in full", () => {
    const statement = buildStatement(presentGrant(), {
      verifiedOrigin: VERIFIED_ORIGIN,
      expiry: EXPIRES,
    });
    expect(statement.primaryText).toContain(VERIFIED_ORIGIN);
  });

  it("never names the manifest name or the SIWE domain", () => {
    const statement = buildStatement(presentGrant(), {
      verifiedOrigin: VERIFIED_ORIGIN,
      expiry: EXPIRES,
    });
    expect(statement.primaryText).not.toContain(MANIFEST_NAME);
    expect(statement.primaryText).not.toContain(SIWE_DOMAIN);
  });

  it("formats the expiry as a UTC timestamp", () => {
    const statement = buildStatement(presentGrant(), {
      verifiedOrigin: VERIFIED_ORIGIN,
      expiry: EXPIRES,
    });
    expect(statement.primaryText).toContain("until 2026-08-07 00:00 UTC");
  });

  it("falls back to a generic requester when no origin was verified", () => {
    const statement = buildStatement(presentGrant(), {
      verifiedOrigin: null,
      expiry: EXPIRES,
    });
    expect(statement.primaryText).not.toContain("https://");
    expect(statement.primaryText).not.toContain(MANIFEST_NAME);
    expect(statement.primaryText).toContain("An unverified requester");
  });

  it("states no expiry and never echoes an unparseable expiry", () => {
    const statement = buildStatement(presentGrant(), {
      verifiedOrigin: VERIFIED_ORIGIN,
      expiry: "not-a-date",
    });
    expect(statement.primaryText).not.toContain("not-a-date");
    expect(statement.primaryText).toContain("with no expiry stated");
  });
});

describe("parse: requester display for held credential presentation", () => {
  it("shows the verified origin as the requester when presenting", () => {
    const model = parseCapabilityReview(parseContext(PRESENT_MESSAGE));
    expect(model.requester.displayName).toBe(VERIFIED_ORIGIN);
  });

  it("keeps the requester unchanged when no presentation is requested", () => {
    const message = siweWithRecap(
      presentRecap(["tinycloud.credentials/get"]),
    );
    const model = parseCapabilityReview(parseContext(message));
    expect(model.requester.displayName).toBe(SIWE_DOMAIN);
  });

  it("keeps the requester unchanged when no origin was verified", () => {
    const model = parseCapabilityReview(
      parseContext(PRESENT_MESSAGE, { verifiedOrigin: null }),
    );
    expect(model.requester.displayName).toBe(SIWE_DOMAIN);
  });
});
