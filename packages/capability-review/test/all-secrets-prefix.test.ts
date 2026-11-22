// TC-3800: decrypt or key creation on `default/secrets` itself, on any prefix under `secrets/`, or on a path that only
// reads as one of them once lower-cased and percent-decoded (`Secrets/`, `secrets%2F`) reads as all secrets: the
// all-secrets card, a one-hour start, 7 days at most, and never one secret. One secret's own key still reads as that
// one secret.

import { describe, expect, it } from "bun:test";

import {
  SECRET_GRANT_MAX_SECONDS,
  allSecretsAbility,
  allSecretsReach,
  approvalLifetimeCapSeconds,
  buildSummaryStatements,
  grantIsBroadOnce,
  oneNamedSecret,
  parseCapabilityReview,
  secretLifetimeCapApplies,
} from "../src/index.js";
import type { CapabilityGrant } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const SECRETS_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:secrets`;
const DECRYPT = "tinycloud.encryption/decrypt";
const CREATE = "tinycloud.encryption/key.create";
const READ_OPENAI = { [`${SECRETS_SPACE}/kv/vault/secrets/OPENAI_API_KEY`]: ["tinycloud.kv/get"] };

function grantsFor(att: Record<string, string[]>): CapabilityGrant[] {
  return parseCapabilityReview({
    message: siweWithResources([
      makeRecapResource(
        Object.fromEntries(Object.entries(att).map(([resource, abilities]) => [resource, Object.fromEntries(abilities.map((a) => [a, [{}]]))])),
      ),
    ]),
    signer: { label: "Key", address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "TinyCloud CLI",
      verifiedOrigin: null,
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
  }).permissions;
}

/** The secret's value in the vault plus the encryption grant: what a one-secret request carries. */
const request = (tail: string, abilities: string[] = [DECRYPT]) => grantsFor({ ...READ_OPENAI, [`${NETWORK}${tail}`]: abilities });
const encryptionGrant = (grants: CapabilityGrant[]) => grants.find((grant) => grant.service.endsWith("encryption"))!;

const ALL_SECRETS_TAILS = [
  "/secrets/",
  "/secrets",
  "/secrets/scoped/work/",
  "/secrets/scoped/",
  "/Secrets/",
  "/SECRETS/",
  "/SECRETS/x",
  "/Secrets/openai_api_key",
  "/secrets%2F",
  "/secrets%2f",
  "/secrets%2Fopenai_api_key",
  "/secrets%2fx",
];

describe("a grant on every secret reads as all secrets, never one secret", () => {
  it.each(ALL_SECRETS_TAILS)("decrypt on default%s", (tail: string) => {
    const grants = request(tail);
    expect(allSecretsReach(grants)).toEqual({ kind: "read", alsoWholeAccount: false });
    expect(allSecretsAbility(encryptionGrant(grants), DECRYPT)).toBe("prefix-decrypt");
    expect(oneNamedSecret(grants)).toBeNull();
    expect(buildSummaryStatements(grants).map((row) => row.primaryText)).not.toContain("Read the secret OPENAI_API_KEY");
    expect(grants.some(grantIsBroadOnce)).toBe(true);
    expect(secretLifetimeCapApplies(grants, { networkDecrypt: false })).toBe(true);
    expect(approvalLifetimeCapSeconds(grants, 30 * 86_400)).toBe(SECRET_GRANT_MAX_SECONDS);
  });

  it.each(ALL_SECRETS_TAILS)("key creation on default%s reads and adds all secrets", (tail: string) => {
    const grants = request(tail, [DECRYPT, CREATE]);
    expect(allSecretsReach(grants)).toEqual({ kind: "read-and-add", alsoWholeAccount: false });
    expect(allSecretsAbility(encryptionGrant(grants), CREATE)).toBe("prefix-create");
    expect(oneNamedSecret(grants)).toBeNull();
    expect(secretLifetimeCapApplies(request(tail, [CREATE]), { networkDecrypt: false })).toBe(true);
  });

  it("a path decoded twice (secrets%252F) still reads as all secrets", () => {
    expect(allSecretsReach(request("/secrets%252F"))).toEqual({ kind: "read", alsoWholeAccount: false });
  });
});

// The bare `secrets` key, written in a form the node's key grammar refuses, so it reads only once lower-cased and
// percent-decoded: exactly `default/secrets`, with no trailing slash.
describe("the bare secrets key in an unreadable form reads as all secrets", () => {
  it.each(["/Secrets", "/SECRETS", "/secret%73", "/Secret%53", "/%53ecrets"])(
    "decrypt on default%s",
    (tail: string) => {
      const grants = request(tail);
      expect(allSecretsAbility(encryptionGrant(grants), DECRYPT)).toBe("prefix-decrypt");
      expect(allSecretsReach(grants)).toEqual({ kind: "read", alsoWholeAccount: false });
      expect(oneNamedSecret(grants)).toBeNull();
      expect(approvalLifetimeCapSeconds(grants, 30 * 86_400)).toBe(SECRET_GRANT_MAX_SECONDS);
    },
  );
});

describe("grants that are not all secrets keep their own reading", () => {
  it("one secret's own key reads as that one secret, with no all-secrets card", () => {
    const grants = request("/secrets/openai_api_key");
    expect(allSecretsReach(grants)).toBeNull();
    expect(oneNamedSecret(grants)).toBe("OPENAI_API_KEY");
    expect(buildSummaryStatements(grants).map((row) => row.primaryText)).toEqual(["Read the secret OPENAI_API_KEY"]);
    expect(grants.some(grantIsBroadOnce)).toBe(false);
    expect(secretLifetimeCapApplies(grants, { networkDecrypt: false })).toBe(true);
  });

  it.each([
    ["a sibling name (secretsx/)", "/secretsx/"],
    ["another folder that is unreadable (Share/)", "/Share/"],
    ["secrets under one app's keys (apps/x/secrets/)", "/apps/xyz.tinycloud.listen/secrets/"],
  ])("%s", (_name: string, tail: string) => {
    expect(allSecretsReach(request(tail))).toBeNull();
  });

  it("secrets/ on another network", () => {
    expect(allSecretsReach(grantsFor({ [`urn:tinycloud:encryption:${OWNER}:work/secrets/`]: [DECRYPT] }))).toBeNull();
  });
});
