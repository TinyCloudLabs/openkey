// TC-128: the review names ONE exact request, credentials.org's held-credentials
// grant, and nothing near it. The grant stays family `unknown` (severity
// unchanged); only the words change. Every near miss keeps the generic copy.

import { describe, expect, it } from "bun:test";

import {
  buildStatements,
  classifyRecapEntry,
  classifySeverityFromActions,
  grantReachesSecretDataOrDecryption,
  parseCapabilityReview,
  sensitiveCallout,
  type CapabilityAction,
  type CapabilityGrant,
  type SignerInfo,
} from "../src/index.js";
import { isHeldCredentialsGrant } from "../src/held-credentials.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const ACCOUNT = FIXTURE_META.address;
const OTHER = "0x2222222222222222222222222222222222222222";
const HELD_LABEL = "Verified email credentials";
const HELD_SENTENCE = "Manage your verified email credentials";
const GENERIC_LABEL = "Unrecognized key-value data";
const GENERIC_SENTENCE = "Read, change and delete your data";
const FOUR = ["get", "list", "put", "del"];

const signer: SignerInfo = {
  label: "Test signer",
  address: ACCOUNT,
  chainId: FIXTURE_META.chainId,
  provenance: "managed",
};

const space = (name: string, owner = ACCOUNT, chain = 1) =>
  `tinycloud:pkh:eip155:${chain}:${owner}:${name}`;
const qualified = (verbs: string[]) => verbs.map((verb) => `tinycloud.kv/${verb}`);

function review(resources: Record<string, string[]>) {
  const att: Record<string, Record<string, unknown[]>> = {};
  for (const [resource, abilities] of Object.entries(resources)) {
    att[resource] = Object.fromEntries(abilities.map((ability) => [ability, [{}]]));
  }
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)]),
    signer,
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "credentials.org",
      verifiedOrigin: "https://credentials.org",
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
  });
}

/** The single grant a one-resource request parses to, with its rows. */
function only(resource: string, abilities: string[]) {
  const model = review({ [resource]: abilities });
  expect(model.permissions).toHaveLength(1);
  const grant = model.permissions[0]!;
  return { grant, rows: buildStatements(grant) };
}

const HELD_RESOURCE = `${space("credentials")}/kv/v1/held/`;

describe("held-credentials request, exact shape", () => {
  it("gets the Advanced title and the one-line sentence, and stays unknown + sensitive", () => {
    const { grant, rows } = only(HELD_RESOURCE, qualified(FOUR));
    expect(grant.family).toBe("unknown");
    expect(grant.severity).toBe("sensitive");
    expect(grant.displayLabel).toBe(HELD_LABEL);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.primaryText).toBe(HELD_SENTENCE);
    expect(rows[0]!.service).toBe("tinycloud.kv");
    expect(rows[0]!.resource).toBe(HELD_RESOURCE);
    expect(rows[0]!.literalEscaped).toBeUndefined();
    expect(rows[0]!.showsRawText).toBeUndefined();
    expect(rows[0]!.severity).toBeUndefined();
  });

  it("labels the real recap the sign-in produced (own space, node form, four actions)", () => {
    const model = review({
      [`${space("credentials")}/kv/app-state/`]: qualified([...FOUR, "metadata"]),
      [`${space("credentials")}/kv/payloads/`]: qualified([...FOUR, "metadata"]),
      [HELD_RESOURCE]: qualified(FOUR),
    });
    const held = model.permissions.find((grant) => grant.path === "v1/held/")!;
    expect(held.displayLabel).toBe(HELD_LABEL);
    for (const sibling of model.permissions.filter((grant) => grant !== held)) {
      expect(sibling.displayLabel).toBe(GENERIC_LABEL);
    }
  });

  it("does not add the grant to the secrets-or-decryption callout", () => {
    const { grant } = only(HELD_RESOURCE, qualified(FOUR));
    expect(grantReachesSecretDataOrDecryption(grant)).toBe(false);
    expect(
      sensitiveCallout([grant].filter(grantReachesSecretDataOrDecryption).length),
    ).toBe("0 permissions reach secrets or decryption");
  });

  it("keeps the severity table: unknown family with a mutation is sensitive", () => {
    expect(classifySeverityFromActions("unknown", qualified(FOUR))).toBe("sensitive");
  });

  it("classifyRecapEntry returns family unknown with the Advanced title", () => {
    expect(
      classifyRecapEntry({
        service: "tinycloud.kv",
        space: space("credentials"),
        path: "v1/held/",
        actions: qualified(FOUR),
        signerAddress: ACCOUNT,
      }),
    ).toEqual({ family: "unknown", displayLabel: HELD_LABEL });
  });

  it("accepts the owner in any letter case", () => {
    expect(
      classifyRecapEntry({
        service: "tinycloud.kv",
        space: space("credentials", ACCOUNT.toUpperCase().replace("0X", "0x")),
        path: "v1/held/",
        actions: qualified(FOUR),
        signerAddress: ACCOUNT,
      }).displayLabel,
    ).toBe(HELD_LABEL);
  });

  it("gives the held row its own text, so it never merges with the generic rows beside it", () => {
    const model = review({
      [`${space("credentials")}/kv/app-state/`]: qualified([...FOUR, "metadata"]),
      [HELD_RESOURCE]: qualified(FOUR),
    });
    const texts = model.permissions.flatMap((grant) =>
      buildStatements(grant).map((row) => row.primaryText),
    );
    expect(texts.sort()).toEqual([GENERIC_SENTENCE, HELD_SENTENCE].sort());
  });
});

describe("held-credentials request, near misses keep the generic copy", () => {
  // Each case: the resource, the abilities, and what the review shows today.
  interface NearMiss {
    name: string;
    resource: string;
    abilities: string[];
    family: CapabilityGrant["family"];
    label: string;
    sentence: string;
    literal: boolean;
  }
  const own = (path: string, name = "credentials", abilities = qualified(FOUR)) => ({
    resource: `${space(name)}/kv/${path}`,
    abilities,
  });
  const generic = (
    name: string,
    input: { resource: string; abilities: string[] },
    sentence = GENERIC_SENTENCE,
  ): NearMiss => ({
    name,
    ...input,
    family: "unknown",
    label: GENERIC_LABEL,
    sentence,
    literal: true,
  });

  const cases: NearMiss[] = [
    generic("space credentials2", own("v1/held/", "credentials2")),
    generic("space messages", own("v1/held/", "messages")),
    generic("space Credentials (case)", own("v1/held/", "Credentials")),
    {
      name: "space applications",
      ...own("v1/held/", "applications"),
      family: "own-app-data",
      label: "Application data",
      sentence: GENERIC_SENTENCE,
      literal: false,
    },
    generic("another owner", {
      resource: `${space("credentials", OTHER)}/kv/v1/held/`,
      abilities: qualified(FOUR),
    }, "Read, change and delete another user's data"),
    generic("another chain id", {
      resource: `${space("credentials", ACCOUNT, 5)}/kv/v1/held/`,
      abilities: qualified(FOUR),
    }),
    generic("path v1/held", own("v1/held")),
    generic("path v1/held/x", own("v1/held/x")),
    generic("path v1/", own("v1/")),
    generic("path v2/held/", own("v2/held/")),
    generic("path V1/held/", own("V1/held/")),
    generic("path v1/held//", own("v1/held//")),
    generic("account suffix path v1/held/0xabc/", own("v1/held/0xabc/")),
    generic("3 actions (no del)", own("v1/held/", "credentials", qualified(["get", "list", "put"])), "Read and change your data"),
    generic("3 actions (no get)", own("v1/held/", "credentials", qualified(["list", "put", "del"]))),
    generic("3 actions (no list)", own("v1/held/", "credentials", qualified(["get", "put", "del"]))),
    generic("3 actions (no put)", own("v1/held/", "credentials", qualified(["get", "list", "del"])), "Read and delete your data"),
    generic("5 actions (+metadata)", own("v1/held/", "credentials", qualified([...FOUR, "metadata"]))),
    generic("delete alias in place of del", own("v1/held/", "credentials", qualified(["get", "list", "put", "delete"]))),
    generic("del and delete together", own("v1/held/", "credentials", qualified([...FOUR, "delete"]))),
    generic("short-form abilities", own("v1/held/", "credentials", FOUR.map((verb) => `kv/${verb}`))),
  ];

  for (const miss of cases) {
    it(`${miss.name}`, () => {
      const { grant, rows } = only(miss.resource, miss.abilities);
      expect(grant.family).toBe(miss.family);
      expect(grant.displayLabel).toBe(miss.label);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.primaryText).toBe(miss.sentence);
      expect(rows[0]!.literalEscaped === true).toBe(miss.literal);
      expect(rows.some((row) => row.primaryText === HELD_SENTENCE)).toBe(false);
    });
  }

  it("a service mismatch (resource segment sql) keeps the raw fallback", () => {
    const { grant, rows } = only(`${space("credentials")}/sql/v1/held/`, qualified(FOUR));
    expect(grant.serviceMismatch).toBe(true);
    expect(grant.displayLabel).not.toBe(HELD_LABEL);
    expect(rows[0]!.primaryText).not.toBe(HELD_SENTENCE);
    expect(rows[0]!.literalEscaped).toBe(true);
  });

  it("another service on the same space and path is not the held request", () => {
    const { grant, rows } = only(
      `${space("credentials")}/sql/v1/held/`,
      ["tinycloud.sql/read", "tinycloud.sql/write"],
    );
    expect(grant.displayLabel).not.toBe(HELD_LABEL);
    expect(rows[0]!.primaryText).not.toBe(HELD_SENTENCE);
  });

  it("an unproven owner (no signer address) is not the held request", () => {
    for (const signerAddress of [null, undefined]) {
      expect(
        classifyRecapEntry({
          service: "tinycloud.kv",
          space: space("credentials"),
          path: "v1/held/",
          actions: qualified(FOUR),
          signerAddress,
        }),
      ).toEqual({ family: "unknown", displayLabel: GENERIC_LABEL });
    }
  });

  it("a signer who is not the space owner is not the held request", () => {
    expect(
      classifyRecapEntry({
        service: "tinycloud.kv",
        space: space("credentials", OTHER),
        path: "v1/held/",
        actions: qualified(FOUR),
        signerAddress: ACCOUNT,
      }).displayLabel,
    ).toBe(GENERIC_LABEL);
  });

  it("a grant whose ownership is unproven or foreign gets the generic sentence", () => {
    const { grant } = only(HELD_RESOURCE, qualified(FOUR));
    for (const ownedBySelf of [null, false] as const) {
      const rows = buildStatements({ ...grant, ownedBySelf });
      expect(rows[0]!.primaryText).not.toBe(HELD_SENTENCE);
      expect(rows[0]!.literalEscaped).toBe(true);
    }
  });
});

describe("held-credentials predicate", () => {
  const base = {
    service: "tinycloud.kv",
    space: space("credentials"),
    path: "v1/held/",
    abilities: qualified(FOUR),
    ownedBySigner: true,
  };

  it("is true for the exact shape in any ability order", () => {
    expect(isHeldCredentialsGrant(base)).toBe(true);
    expect(isHeldCredentialsGrant({ ...base, abilities: qualified([...FOUR].reverse()) })).toBe(true);
  });

  it("is false when any one field deviates", () => {
    expect(isHeldCredentialsGrant({ ...base, ownedBySigner: false })).toBe(false);
    expect(isHeldCredentialsGrant({ ...base, serviceMismatch: true })).toBe(false);
    expect(isHeldCredentialsGrant({ ...base, service: "kv" })).toBe(false);
    expect(isHeldCredentialsGrant({ ...base, space: space("applications") })).toBe(false);
    expect(isHeldCredentialsGrant({ ...base, path: "v1/held" })).toBe(false);
    expect(isHeldCredentialsGrant({ ...base, abilities: qualified(["get", "list", "put"]) })).toBe(false);
    expect(isHeldCredentialsGrant({ ...base, abilities: qualified([...FOUR, "metadata"]) })).toBe(false);
    expect(isHeldCredentialsGrant({ ...base, abilities: qualified(["get", "get", "put", "del"]) })).toBe(false);
    expect(isHeldCredentialsGrant({ ...base, abilities: FOUR })).toBe(false);
  });

  it("classify and statements both answer from it (they cannot drift)", () => {
    // A grant the predicate rejects is rejected by both; one it accepts is
    // accepted by both. Build hand-made grants so only the predicate inputs vary.
    const action = (ability: string): CapabilityAction => ({
      id: ability,
      ability,
      verb: ability.slice(ability.indexOf("/") + 1),
      required: false,
      selected: true,
      editable: true,
      caveats: [],
    });
    const grantFor = (path: string): CapabilityGrant => ({
      id: path,
      family: "unknown",
      severity: "sensitive",
      service: "tinycloud.kv",
      space: space("credentials"),
      path,
      owner: ACCOUNT,
      ownedBySelf: true,
      displayLabel: GENERIC_LABEL,
      metadataLabel: null,
      resourceService: "kv",
      actions: qualified(FOUR).map(action),
    });
    for (const path of ["v1/held/", "v1/held", "v1/held/x"]) {
      const viaClassify =
        classifyRecapEntry({
          service: "tinycloud.kv",
          space: space("credentials"),
          path,
          actions: qualified(FOUR),
          signerAddress: ACCOUNT,
        }).displayLabel === HELD_LABEL;
      const viaStatements = buildStatements(grantFor(path))[0]!.primaryText === HELD_SENTENCE;
      expect(viaClassify).toBe(viaStatements);
      expect(viaClassify).toBe(path === "v1/held/");
    }
  });
});
