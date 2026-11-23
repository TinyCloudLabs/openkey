import { describe, expect, test } from "bun:test";
import { attenuableDelegationLine, parseCapabilityReview } from "../src/index.js";
import { FIXTURE_META, siweWithResources } from "./fixtures/index.js";

const SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default`;
const ATT = { [`${SPACE}/kv/notes/`]: { "tinycloud.kv/get": [{}] } };

function recapWith(payload: Record<string, unknown>): string {
  const b64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return siweWithResources([`urn:recap:${b64}`]);
}

function parse(message: string, delegationMode?: "terminal" | "attenuable") {
  return parseCapabilityReview({
    message,
    signer: {
      label: "Key",
      address: FIXTURE_META.address,
      chainId: FIXTURE_META.chainId,
      provenance: "managed",
    },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "app.example.com",
      verifiedOrigin: "https://app.example.com",
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    ...(delegationMode !== undefined ? { delegationMode } : {}),
  });
}

describe("capability-review delegationMode parsing and consent line copy", () => {
  test("extracts terminal and attenuable from top-level ReCap field, omitting when absent", () => {
    const absent = parse(recapWith({ att: ATT, prf: [] }));
    expect(absent.protocol).toBe("tinycloud-siwe-recap");
    expect(absent.delegationMode).toBeUndefined();

    const terminal = parse(
      recapWith({ att: ATT, prf: [], "xyz.tinycloud.policy/delegationMode": "terminal" }),
    );
    expect(terminal.protocol).toBe("tinycloud-siwe-recap");
    expect(terminal.delegationMode).toBe("terminal");

    const attenuable = parse(
      recapWith({ att: ATT, prf: [], "xyz.tinycloud.policy/delegationMode": "attenuable" }),
    );
    expect(attenuable.protocol).toBe("tinycloud-siwe-recap");
    expect(attenuable.delegationMode).toBe("attenuable");
  });

  test("falls back to request-level delegationMode when ReCap omits it, but ReCap value wins", () => {
    const fromRequest = parse(recapWith({ att: ATT, prf: [] }), "attenuable");
    expect(fromRequest.delegationMode).toBe("attenuable");

    const recapWins = parse(
      recapWith({ att: ATT, prf: [], "xyz.tinycloud.policy/delegationMode": "terminal" }),
      "attenuable",
    );
    expect(recapWins.delegationMode).toBe("terminal");
  });

  test("warns and does not accept invalid delegationMode values in ReCap", () => {
    const bad = parse(recapWith({ att: ATT, prf: [], "xyz.tinycloud.policy/delegationMode": "Attenuable" }));
    expect(bad.delegationMode).toBeUndefined();
    expect(bad.parseWarnings.some((w) => w.code === "unrecognized-recap-namespace")).toBe(true);
  });

  test("attenuableDelegationLine uses Monica's verbatim wording with app placeholder and fallback", () => {
    expect(attenuableDelegationLine("app.example.com")).toBe(
      "app.example.com can share this access with other apps or agents it works with.",
    );
    expect(attenuableDelegationLine("TinyChat")).toBe(
      "TinyChat can share this access with other apps or agents it works with.",
    );
    expect(attenuableDelegationLine(null)).toBe(
      "This app can share this access with other apps or agents it works with.",
    );
    expect(attenuableDelegationLine("   ")).toBe(
      "This app can share this access with other apps or agents it works with.",
    );
  });
});
