import { expect, test } from "bun:test";
import { isFirstPartyEncryptionOrigin } from "../src/first-party-origins";

// The widget reads this list to refuse an outside site's encryption request before Approve. The signing route enforces
// the same list from the API's own copy; first-party-origins-parity.test.ts keeps the two identical.
test("https://tinycloud.one is first-party", () => {
  expect(isFirstPartyEncryptionOrigin("https://tinycloud.one")).toBe(true);
});

test("look-alikes of https://tinycloud.one are not first-party", () => {
  for (const origin of [
    "https://tinycloud.one.evil.example",
    "https://evil-tinycloud.one",
    "https://www.tinycloud.one",
    "https://other.tinycloud.one",
    "https://tinycloud.one:8443",
    "http://tinycloud.one",
    "https://TINYCLOUD.ONE",
  ]) expect(isFirstPartyEncryptionOrigin(origin)).toBe(false);
});
