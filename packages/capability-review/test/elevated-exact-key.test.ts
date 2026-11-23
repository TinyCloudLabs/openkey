import { describe, expect, test } from "bun:test";
import { elevatedCard, elevatedExactKey, elevatedKindOf, elevatedWhere, elevatedWhereText } from "../src/index";

const OWNER = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = "tinycloud.encryption/";
const parserForm = (resource: string) => ({ service: "encryption", space: "encryption", path: resource });
const reportedForm = (resource: string) => ({ service: "tinycloud.encryption", space: resource, path: "" });

// A key URN has no trailing "/" and a prefix has exactly one; that is the only thing that tells the two apart.
describe("elevatedExactKey", () => {
  test.each([
    ["an exact key", urn("/share/abc"), "abc"],
    ["an exact key one segment deep", urn("/qa"), "qa"],
    ["an exact key several segments deep", urn("/a/b/c"), "c"],
  ])("%s names its last segment, in either entry form", (_name, resource, name) => {
    expect(elevatedExactKey(parserForm(resource))).toBe(name);
    expect(elevatedExactKey(reportedForm(resource))).toBe(name);
    expect(elevatedWhere(parserForm(resource))).toBe(name);
  });

  test.each([
    ["a prefix (trailing slash)", urn("/share/")],
    ["a one-segment prefix", urn("/qa/")],
    ["a nested prefix", urn("/a/b/")],
    ["the whole network", urn("")],
    ["a network with an empty path", urn("/")],
    ["a path the key grammar refuses", urn("/Share/ABC")],
    ["an empty segment", urn("/a//b")],
    ["a URN in another letter case", urn("/share/abc").toUpperCase()],
  ])("%s is not one key", (_name, resource) => {
    expect(elevatedExactKey(parserForm(resource))).toBeNull();
    expect(elevatedExactKey(reportedForm(resource))).toBeNull();
  });

  test("a non-encryption entry is not one key", () => {
    expect(elevatedExactKey({ service: "kv", space: "s", path: "share/abc" })).toBeNull();
  });

  test("the elevated kind is the same for the key and its prefix; only the trailing slash differs", () => {
    expect(elevatedKindOf(parserForm(urn("/share/abc")), `${E}decrypt`)).toBe("encryption-keys");
    expect(elevatedKindOf(parserForm(urn("/share/")), `${E}decrypt`)).toBe("encryption-keys");
  });
});

describe("the card for one exact key", () => {
  const both = { decrypt: true, create: true };
  const where = elevatedWhereText("abc");

  test("unlock and create on one key reads in Monica's words", () => {
    expect(elevatedCard("encryption-keys", both, "gk.gbafa.com", where, "abc")).toEqual({
      heading: "Create and use one encryption key: abc",
      body: "gk.gbafa.com could create the encryption key named abc and unlock the items encrypted with it, for as long as this approval lasts. This permission covers only that key.",
    });
  });

  test("with no verified site it names 'This request'", () => {
    expect(elevatedCard("encryption-keys", both, null, where, "abc").body).toStartWith("This request could create the encryption key named abc ");
  });

  test("a folder keeps its card, with or without the exact-key parameter", () => {
    const folder = elevatedWhereText("share");
    const expected = {
      heading: "Unlock and create encrypted items in a folder named share",
      body: "x.test could unlock the encrypted items in a folder named share and create new encryption keys there, for as long as this approval lasts.",
    };
    expect(elevatedCard("encryption-keys", both, "x.test", folder, null)).toEqual(expected);
    expect(elevatedCard("encryption-keys", both, "x.test", folder)).toEqual(expected);
  });

  test("the other exact-key shapes keep their wording", () => {
    const card = (abilities: Parameters<typeof elevatedCard>[1]) => elevatedCard("encryption-keys", abilities, "x.test", where, "abc");
    const folder = (abilities: Parameters<typeof elevatedCard>[1]) => elevatedCard("encryption-keys", abilities, "x.test", where);
    for (const abilities of [
      { decrypt: true, create: false },
      { decrypt: false, create: true },
      { decrypt: true, create: true, block: true },
      { decrypt: false, create: false, unblock: true },
      { decrypt: true, create: true, block: true, unblock: true },
    ]) {
      expect(card(abilities)).toEqual(folder(abilities));
    }
    expect(card({ decrypt: true, create: false }).heading).toBe("Unlock encrypted items in a folder named abc");
  });

  test("a whole network never reads as one key", () => {
    expect(elevatedCard("encryption-network", both, "x.test", elevatedWhereText(null), "abc").heading).toBe("Unlock all your encrypted data");
  });
});
