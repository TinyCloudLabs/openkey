import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

// The widget reads the first-party list from this package; `/api/keys/:keyId/sign` enforces it from the API's own
// copy, because the API runtime image ships only apps/api/src. The two copies are the same bytes.
test("the first-party encryption origins are byte-identical to the API's", () => {
  const api = readFileSync(new URL("../../../apps/api/src/services/first-party-origins.ts", import.meta.url), "utf8");
  const shared = readFileSync(new URL("../src/first-party-origins.ts", import.meta.url), "utf8");
  expect(shared).toBe(api);
});
