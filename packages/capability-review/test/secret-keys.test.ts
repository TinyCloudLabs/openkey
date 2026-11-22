// TC-3800: one secret's own key (`default/secrets/<name>`) reads as that one secret and keeps the app's length; a
// grant that can open every secret (a whole network, or the `secrets/` prefix) gets the all-secrets card and the
// one-hour start; any request that decrypts secrets lasts 7 days at most.

import { describe, expect, it } from "bun:test";

import {
  NAMED_SECRET_DECRYPT_ROW,
  SECRET_GRANT_MAX_SECONDS,
  allSecretsCard,
  allSecretsReach,
  approvalLifetimeCapSeconds,
  decryptsSecrets,
  buildSummaryStatements,
  exactSecretKeyPath,
  grantDecryptsOneSecret,
  grantIsBroadOnce,
  oneNamedSecret,
  parseCapabilityReview,
  secretOfKvPath,
  secretLifetimeCapApplies,
} from "../src/index.js";
import type { CapabilityGrant } from "../src/index.js";
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./fixtures/index.js";

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const SECRETS_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:secrets`;
const DECRYPT = "tinycloud.encryption/decrypt";
const CREATE = "tinycloud.encryption/key.create";
const KV_GET = "tinycloud.kv/get";
const OPENAI_KEY = `${NETWORK}/secrets/openai_api_key`;
const READ_OPENAI = { [`${SECRETS_SPACE}/kv/vault/secrets/OPENAI_API_KEY`]: [KV_GET] };
const ALL_SECRETS = `${NETWORK}/secrets/`;

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

const rows = (att: Record<string, string[]>) =>
  buildSummaryStatements(grantsFor(att)).map((row) => [row.primaryText, row.severity, row.detail ?? null]);

describe("secret key paths", () => {
  it("names one secret's exact key, global or scoped, lowercase only", () => {
    expect(exactSecretKeyPath(OPENAI_KEY)).toBe("secrets/openai_api_key");
    expect(exactSecretKeyPath(`${NETWORK}/secrets/scoped/work.team/openai_api_key`)).toBe("secrets/scoped/work.team/openai_api_key");
    for (const tail of ["secrets/", "secrets/OPENAI_API_KEY", "secrets/scoped/work", "secrets/scoped/work/", "secrets/a/b", "share/x", "openai"]) {
      expect(exactSecretKeyPath(`${NETWORK}/${tail}`), tail).toBeNull();
    }
    expect(exactSecretKeyPath(NETWORK)).toBeNull();
    expect(exactSecretKeyPath(`urn:tinycloud:encryption:${OWNER}:team/secrets/openai_api_key`)).toBeNull();
  });

  it("maps a secret's KV path to its key, and nothing else", () => {
    expect(secretOfKvPath("vault/secrets/OPENAI_API_KEY")).toEqual({ name: "OPENAI_API_KEY", keyPath: "secrets/openai_api_key" });
    expect(secretOfKvPath("vault/secrets/scoped/listen/API_KEY")).toEqual({ name: "API_KEY", keyPath: "secrets/scoped/listen/api_key" });
    for (const path of ["vault/secrets/", "vault/secrets/lower", "vault/secrets/scoped/listen/", `vault/secrets/A${"B".repeat(64)}`, "vault/other/KEY"]) {
      expect(secretOfKvPath(path), path).toBeNull();
    }
  });
});

describe("one secret's own key in the summary", () => {
  it("a read and decrypt of one secret is one row with the secret's name (W1)", () => {
    const grants = grantsFor({ ...READ_OPENAI, [OPENAI_KEY]: [DECRYPT] });
    expect(oneNamedSecret(grants)).toBe("OPENAI_API_KEY");
    expect(buildSummaryStatements(grants).map((row) => [row.key, row.primaryText])).toEqual([[NAMED_SECRET_DECRYPT_ROW, "Read the secret OPENAI_API_KEY"]]);
  });

  it("key.create on one secret's key says it can't read any secret (W4), under the row", () => {
    expect(rows({ [OPENAI_KEY]: [CREATE] })).toEqual([
      ["Create a key for the new secret openai_api_key.", "attention", "It can't read any of your secrets."],
    ]);
  });

  it("names the secret from the KV path the request pairs with its key, beside other permissions", () => {
    const notes = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default/kv/notes/`;
    const summary = rows({ ...READ_OPENAI, [OPENAI_KEY]: [DECRYPT, CREATE], [notes]: [KV_GET] });
    expect(summary).toContainEqual(["Read the secret OPENAI_API_KEY", "sensitive", null]);
    expect(summary).toContainEqual(["Create a key for the new secret OPENAI_API_KEY.", "attention", "It can't read any of your secrets."]);
    expect(summary.filter(([text]) => text === "Read the secret OPENAI_API_KEY")).toHaveLength(1);
  });

  it("an exact secret key keeps the app's length; the secrets/ prefix and a whole network start at one hour", () => {
    expect(grantsFor({ [OPENAI_KEY]: [DECRYPT] }).some(grantIsBroadOnce)).toBe(false);
    expect(grantsFor({ [ALL_SECRETS]: [DECRYPT] }).some(grantIsBroadOnce)).toBe(true);
    expect(grantsFor({ [NETWORK]: [DECRYPT] }).some(grantIsBroadOnce)).toBe(true);
    expect(grantsFor({ [OPENAI_KEY]: [DECRYPT] }).some(grantDecryptsOneSecret)).toBe(true);
    expect(grantsFor({ [OPENAI_KEY]: [CREATE] }).some(grantDecryptsOneSecret)).toBe(false);
  });
});

describe("the all-secrets card", () => {
  it("today's TinyChat shape (one secret's KV read + network decrypt) gets the all-secrets card, not the one-secret wording", () => {
    const grants = grantsFor({ ...READ_OPENAI, [NETWORK]: [DECRYPT] });
    expect(oneNamedSecret(grants)).toBeNull();
    expect(buildSummaryStatements(grants).map((row) => row.primaryText)).not.toContain("Read the secret OPENAI_API_KEY");
    expect(allSecretsReach(grants)).toEqual({ kind: "whole-account", alsoWholeAccount: false });
    expect(grants.some(grantIsBroadOnce)).toBe(true);
  });

  it("an exact key beside a network decrypt is still the whole account, not one secret", () => {
    const grants = grantsFor({ ...READ_OPENAI, [OPENAI_KEY]: [DECRYPT], [NETWORK]: [DECRYPT] });
    expect(oneNamedSecret(grants)).toBeNull();
    expect(allSecretsReach(grants)).toEqual({ kind: "whole-account", alsoWholeAccount: false });
    expect(grants.some(grantIsBroadOnce)).toBe(true);
  });

  it("picks the heading by what the request reaches, first match wins", () => {
    const reach = (att: Record<string, string[]>) => allSecretsReach(grantsFor(att));
    // Secret Manager's /app: network decrypt, secrets/ decrypt and create.
    expect(reach({ [NETWORK]: [DECRYPT], [ALL_SECRETS]: [DECRYPT, CREATE] })).toEqual({ kind: "read-and-add", alsoWholeAccount: true });
    expect(reach({ [ALL_SECRETS]: [DECRYPT, CREATE] })).toEqual({ kind: "read-and-add", alsoWholeAccount: false });
    expect(reach({ [ALL_SECRETS]: [DECRYPT] })).toEqual({ kind: "read", alsoWholeAccount: false });
    expect(reach({ [ALL_SECRETS]: [DECRYPT], [NETWORK]: [DECRYPT] })).toEqual({ kind: "read", alsoWholeAccount: true });
    expect(reach({ [NETWORK]: [DECRYPT] })).toEqual({ kind: "whole-account", alsoWholeAccount: false });
    // key.create on secrets/ reads nothing; one secret's key is not every secret.
    expect(reach({ [ALL_SECRETS]: [CREATE] })).toBeNull();
    expect(reach({ ...READ_OPENAI, [OPENAI_KEY]: [DECRYPT, CREATE] })).toBeNull();
  });

  it("says Monica's W3 words, with the older-data sentence only beside a network decrypt", () => {
    const trust = "Allow this only for your own tools on a device you trust.";
    expect(allSecretsCard({ kind: "read-and-add", alsoWholeAccount: true }, "secrets.tinycloud.xyz")).toEqual({
      heading: "Let secrets.tinycloud.xyz read and add all your secrets?",
      body: `It can also open older encrypted data on your account. ${trust}`,
      cue: null,
    });
    expect(allSecretsCard({ kind: "read", alsoWholeAccount: false }, "secrets.tinycloud.xyz")).toEqual({
      heading: "Let secrets.tinycloud.xyz read all your secrets?",
      body: trust,
      cue: null,
    });
    expect(allSecretsCard({ kind: "whole-account", alsoWholeAccount: false }, null)).toEqual({
      heading: "Let this app open all your encrypted data?",
      body: "That covers every secret and everything else you've encrypted in TinyCloud. Allow this only for an app you trust.",
      cue: "OpenKey can't confirm which site asked.",
    });
  });
});

describe("the 7-day cap on secrets", () => {
  const entry = (path: string, actions: string[]) => ({ service: "tinycloud.encryption", space: "encryption", path, actions });
  const MONTH = 30 * 24 * 60 * 60;

  it("caps a request that decrypts a secret's key, a prefix under secrets/ or a whole network at 7 days", () => {
    const paths = [
      OPENAI_KEY, ALL_SECRETS, `${NETWORK}/secrets/scoped/work/`, `${NETWORK}/secrets/scoped/work/api_key`,
      NETWORK, `urn:tinycloud:encryption:${OWNER}:team-2`,
    ];
    for (const path of paths) {
      expect(approvalLifetimeCapSeconds([entry(path, [DECRYPT])], MONTH), path).toBe(SECRET_GRANT_MAX_SECONDS);
    }
    expect(approvalLifetimeCapSeconds([entry(OPENAI_KEY, [DECRYPT])], 3600)).toBe(3600);
  });

  it("leaves every other request at what it signed", () => {
    for (const [path, actions] of [[OPENAI_KEY, [CREATE]], [NETWORK, [CREATE]], [`${NETWORK}/share/`, [DECRYPT]], [`urn:tinycloud:encryption:${OWNER}:team/secrets/x`, [DECRYPT]]] as const) {
      expect(approvalLifetimeCapSeconds([entry(path, [...actions])], MONTH), path).toBe(MONTH);
    }
    expect(approvalLifetimeCapSeconds([{ service: "tinycloud.kv", space: SECRETS_SPACE, path: "vault/secrets/OPENAI_API_KEY", actions: [KV_GET] }], MONTH)).toBe(MONTH);
  });

  it("caps a decrypt it cannot read the key of, so an unparseable resource never escapes the cap", () => {
    for (const path of ["urn:tinycloud:encryption:not-a-did", "urn:tinycloud:encryption:", "garbage"]) {
      expect(decryptsSecrets([entry(path, [DECRYPT])]), path).toBe(true);
      expect(approvalLifetimeCapSeconds([entry(path, [DECRYPT])], MONTH), path).toBe(SECRET_GRANT_MAX_SECONDS);
      expect(secretLifetimeCapApplies([entry(path, [CREATE])], { networkDecrypt: false }), path).toBe(true);
    }
  });
});

describe("the 7-day cap outside a signed approval request", () => {
  const entry = (path: string, actions: string[]) => ({ service: "tinycloud.encryption", space: "encryption", path, actions });
  const off = { networkDecrypt: false };
  const on = { networkDecrypt: true };

  it("holds decrypt and key.create on a secret's key or a prefix under secrets/, whatever the network flag", () => {
    for (const path of [OPENAI_KEY, ALL_SECRETS, `${NETWORK}/secrets/scoped/work/api_key`, `${NETWORK}/SECRETS/x`]) {
      for (const actions of [[DECRYPT], [CREATE], ["encryption/decrypt"]]) {
        expect(secretLifetimeCapApplies([entry(path, actions)], off), `${path} ${actions}`).toBe(true);
        expect(secretLifetimeCapApplies([entry(path, actions)], on), `${path} ${actions}`).toBe(true);
      }
    }
  });

  it("holds a whole network's decrypt only with the network flag, and never its key.create", () => {
    expect(secretLifetimeCapApplies([entry(NETWORK, [DECRYPT])], off)).toBe(false);
    expect(secretLifetimeCapApplies([entry(NETWORK, [DECRYPT])], on)).toBe(true);
    expect(secretLifetimeCapApplies([entry(NETWORK, [CREATE])], on)).toBe(false);
  });

  it("leaves share/, other folders, other networks and kv alone", () => {
    for (const path of [`${NETWORK}/share/`, `${NETWORK}/qa/`, `urn:tinycloud:encryption:${OWNER}:team/secrets/x`]) {
      expect(secretLifetimeCapApplies([entry(path, [DECRYPT, CREATE])], on), path).toBe(false);
    }
    expect(secretLifetimeCapApplies([{ service: "tinycloud.kv", space: SECRETS_SPACE, path: "vault/secrets/OPENAI_API_KEY", actions: [KV_GET] }], on)).toBe(false);
  });

  it("reads grants parsed from a SIWE the same way", () => {
    expect(secretLifetimeCapApplies(grantsFor({ ...READ_OPENAI, [OPENAI_KEY]: [DECRYPT] }), off)).toBe(true);
    expect(secretLifetimeCapApplies(grantsFor({ [NETWORK]: [DECRYPT] }), off)).toBe(false);
  });
});
