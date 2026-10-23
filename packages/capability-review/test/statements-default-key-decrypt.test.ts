// Raw `tinycloud.encryption/decrypt` on the account's `:default` network is
// the only encryption shape that gets the default-key consent statement.
// Named networks and sub-paths keep the neutral "Decrypt protected data".

import { describe, expect, it } from "bun:test";

import { DECRYPT_DEFAULT_KEY_STATEMENT } from "../src/copy.js";
import {
  buildStatement,
  buildStatements,
  parseCapabilityReview,
} from "../src/index.js";
import type { CapabilityGrant, SignerInfo } from "../src/index.js";
import type { ParseContext } from "../src/parse.js";
import {
  FIXTURE_META,
  makeRecapResource,
  siweWithResources,
} from "./fixtures/index.js";

const ADDRESS = FIXTURE_META.address;
const DEFAULT_NETWORK = `urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:${ADDRESS}:default`;
const TEAM_NETWORK = `urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:${ADDRESS}:team-2`;
const APP_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${ADDRESS}:default`;
const COMBINED_NAMED = "Set up encrypted data access and decrypt protected data";
const SETUP_ONLY = "Set up encrypted data access";
const DECRYPT_NAMED = "Decrypt protected data";
const CREATE = "tinycloud.encryption/network.create";
const DECRYPT = "tinycloud.encryption/decrypt";

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

function parsedStatements(message: string): string[] {
  return parseCapabilityReview(ctx(message))
    .permissions.flatMap((permission) => buildStatements(permission))
    .map((row) => row.primaryText);
}

function encryptionGrant(
  space: string,
  path: string,
  abilities: string[] = [DECRYPT],
): CapabilityGrant {
  return {
    id: `tinycloud.encryption\x00${space}\x00${path}`,
    family: "encryption-decrypt",
    severity: "sensitive",
    service: "tinycloud.encryption",
    space,
    path,
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    resourceService: null,
    actions: abilities.map((ability) => ({
      id: `tinycloud.encryption\x00${space}\x00${path}\x00${ability}`,
      ability,
      verb: ability.slice(ability.indexOf("/") + 1),
      required: false,
      selected: true,
      editable: true,
      caveats: [{}],
    })),
  };
}

function appDataGrant(service: string, abilities: string[]): CapabilityGrant {
  return {
    id: `${service}\x00${APP_SPACE}\x00`,
    family: "own-app-data",
    severity: "attention",
    service,
    space: APP_SPACE,
    path: "",
    owner: null,
    ownedBySelf: true,
    displayLabel: "",
    metadataLabel: null,
    resourceService: null,
    actions: abilities.map((ability) => ({
      id: `${service}\x00${APP_SPACE}\x00\x00${ability}`,
      ability,
      verb: ability.slice(ability.indexOf("/") + 1),
      required: false,
      selected: true,
      editable: true,
      caveats: [{}],
    })),
  };
}

describe("buildStatement — raw decrypt on the account default network", () => {
  it("selects the default-key statement for the :default URN network", () => {
    expect(buildStatement(encryptionGrant(DEFAULT_NETWORK, "")).primaryText).toBe(
      DECRYPT_DEFAULT_KEY_STATEMENT,
    );
  });

  it("keeps 'Decrypt protected data' for a named URN network", () => {
    expect(buildStatement(encryptionGrant(TEAM_NETWORK, "")).primaryText).toBe(
      DECRYPT_NAMED,
    );
  });

  it("keeps 'Decrypt protected data' when the default network carries a sub-path", () => {
    expect(
      buildStatement(encryptionGrant(DEFAULT_NETWORK, "shares/abc")).primaryText,
    ).toBe(DECRYPT_NAMED);
  });
});

describe("default-key decrypt combined with encryption setup", () => {
  it("splits the default network into a setup row and the exact default-key row", () => {
    const grant = encryptionGrant(DEFAULT_NETWORK, "", [CREATE, DECRYPT]);
    expect(buildStatements(grant).map((row) => row.primaryText)).toEqual([
      SETUP_ONLY,
      DECRYPT_DEFAULT_KEY_STATEMENT,
    ]);
  });

  it("keeps the combined sentence for a named network", () => {
    const grant = encryptionGrant(TEAM_NETWORK, "", [CREATE, DECRYPT]);
    expect(buildStatements(grant).map((row) => row.primaryText)).toEqual([
      COMBINED_NAMED,
    ]);
  });

  it("never returns the understated combined sentence for the default network", () => {
    const grant = encryptionGrant(DEFAULT_NETWORK, "", [CREATE, DECRYPT]);
    expect(buildStatement(grant).primaryText).not.toBe(COMBINED_NAMED);
  });
});

describe("buildStatements — default-key decrypt alongside application data", () => {
  it("renders the SQL rows and the default-key row as separate rows", () => {
    const rows = [
      ...buildStatements(
        appDataGrant("tinycloud.sql", [
          "tinycloud.sql/read",
          "tinycloud.sql/write",
          "tinycloud.sql/schema",
        ]),
      ),
      ...buildStatements(encryptionGrant(DEFAULT_NETWORK, "")),
    ].map((row) => row.primaryText);
    expect(rows).toEqual([
      "Read and update application data",
      "Create, change and delete tables in application data",
      DECRYPT_DEFAULT_KEY_STATEMENT,
    ]);
  });

  it("renders the KV rows and the default-key row as separate rows", () => {
    const rows = [
      ...buildStatements(
        appDataGrant("tinycloud.kv", ["tinycloud.kv/get", "tinycloud.kv/put"]),
      ),
      ...buildStatements(encryptionGrant(DEFAULT_NETWORK, "")),
    ].map((row) => row.primaryText);
    expect(rows).toEqual([
      "Read and update application data",
      DECRYPT_DEFAULT_KEY_STATEMENT,
    ]);
  });
});

describe("default-network forms that reach the default-key statement", () => {
  it("A: raw URN ReCap key with a lowercase address", () => {
    expect(
      parsedStatements(
        siweWithResources([
          makeRecapResource({ [DEFAULT_NETWORK]: { [DECRYPT]: [{}] } }),
        ]),
      ),
    ).toEqual([DECRYPT_DEFAULT_KEY_STATEMENT]);
  });

  it("B: raw URN ReCap key with an EIP-55 mixed-case address", () => {
    const network = `urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default`;
    expect(
      parsedStatements(
        siweWithResources([makeRecapResource({ [network]: { [DECRYPT]: [{}] } })]),
      ),
    ).toEqual([DECRYPT_DEFAULT_KEY_STATEMENT]);
  });

  it("C: raw URN ReCap key on a non-1 chain id", () => {
    const network = `urn:tinycloud:encryption:did:pkh:eip155:137:${ADDRESS}:default`;
    expect(
      parsedStatements(
        siweWithResources([makeRecapResource({ [network]: { [DECRYPT]: [{}] } })]),
      ),
    ).toEqual([DECRYPT_DEFAULT_KEY_STATEMENT]);
  });

  it("D: legacy SIWE line 'tinycloud.encryption/decrypt:<default URN>'", () => {
    expect(
      parsedStatements(siweWithResources([`tinycloud.encryption/decrypt:${DEFAULT_NETWORK}`])),
    ).toEqual([DECRYPT_DEFAULT_KEY_STATEMENT]);
  });

  it("E: short service name 'encryption/decrypt:<default URN>'", () => {
    expect(
      parsedStatements(siweWithResources([`encryption/decrypt:${DEFAULT_NETWORK}`])),
    ).toEqual([DECRYPT_DEFAULT_KEY_STATEMENT]);
  });
});

describe("default-network-looking forms that keep the neutral text (known gaps)", () => {
  it("a did:key principal network is not the account's default network", () => {
    const network = "urn:tinycloud:encryption:did:key:z6MkExampleKey:default";
    expect(buildStatement(encryptionGrant(network, "")).primaryText).toBe(
      DECRYPT_NAMED,
    );
  });

  it("an encryption/ pseudo-space prefix keeps the neutral text", () => {
    expect(
      buildStatement(encryptionGrant(`encryption/${DEFAULT_NETWORK}`, "")).primaryText,
    ).toBe(DECRYPT_NAMED);
  });
});
