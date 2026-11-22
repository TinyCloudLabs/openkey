import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { judgeSignFace, judgeTermsCard, scrub } from "./judge.mjs";

const { signFaces, terms } = JSON.parse(readFileSync(new URL("./expected-screens.json", import.meta.url), "utf8"));
const host = { hostOrigin: "https://tinycloud.one" };
const face = (permissions, note = "These permissions renew automatically for up to 90 days", requester = "tinycloud.one") => [
  "Sign Message", "Authorize capabilities", "", `Requested by ${requester}`, "", "Review the access this app is asking for.", "",
  ...permissions, note, "Advanced details", "Requester and signing details", "Requester", requester,
  "Verified browser origin", `https://${requester}`, "Manifest trust", "No signed manifest",
].join("\n");
const expected = signFaces[0].permissions;

test("the TinyCloud One sign-in face is approved, with either expiry note", () => {
  assert.deepEqual(judgeSignFace(face(expected), signFaces, host), { ok: true, face: "tinycloud-one-sign-in" });
  assert.equal(judgeSignFace(face([...expected].reverse(), "These permissions expire in 30 days, on Dec 19"), signFaces, host).ok, true);
});

test("an extra or a missing permission fails closed and names the line", () => {
  const extra = judgeSignFace(face([...expected, "Read, change or delete any row in every database"]), signFaces, host);
  assert.equal(extra.ok, false);
  assert.equal(extra.reason, "permissions");
  assert.deepEqual(extra.extra, ["Read, change or delete any row in every database"]);
  const missing = judgeSignFace(face(expected.slice(1)), signFaces, host);
  assert.deepEqual([missing.ok, missing.reason, missing.missing], [false, "permissions", [expected[0]]]);
});

test("a review requested by another site, or with a forbidden warning, is refused", () => {
  assert.equal(judgeSignFace(face(expected, undefined, "evil.example"), signFaces, host).reason, "requester");
  assert.equal(judgeSignFace(`${face(expected)}\nUnlock all your encrypted data`, signFaces, host).reason, "forbidden_text");
});

test("two expiry notes, or an unrelated screen, are refused", () => {
  assert.equal(judgeSignFace(face(expected, "These permissions renew automatically for up to 90 days\nThese permissions expire in 30 days, on Dec 19"), signFaces, host).reason, "note_count");
  assert.equal(judgeSignFace("Sign in to OpenKey\nContinue with email", signFaces, host).ok, false);
});

test("scrub removes addresses, emails and codes", () => {
  const out = scrub("tcqa+share-okgate-a1-b2@qa-mail.tinycloud.xyz 0xd9Fbf2af3d21311c179775f26B3557B4FDD787d4 code 123456 Bearer abc.def");
  assert.equal(out, "<email> <address> code <6digits> Bearer <token>");
});

// The embedded Terms card's innerText as Chromium lays it out (terms-accept.svelte, embed branch).
const card = (lede = "OpenKey and TinyCloud are run by TinyCloud, Inc. To use your account, agree to our Terms of Service. Our Privacy Policy explains what we collect, why, and your rights.", extra = []) => [
  "Accept the Terms and Privacy Policy", lede, ...extra,
  "Terms of Service, effective Nov 22, 2026", "(opens in a new tab)", "Privacy Policy: what we collect, why, and your rights", "(opens in a new tab)",
  "Agree and continue", "By selecting Agree and continue, you agree to the Terms of Service and acknowledge the Privacy Policy.", "Sign out",
].join("\n");

test("the embedded Terms card for a first agreement is the expected one", () => {
  assert.equal(judgeTermsCard(card(), terms.embedCard.hrefs, terms.embedCard).ok, true);
});

test("a Terms card with other copy, a What changed note, or other links fails closed", () => {
  assert.equal(judgeTermsCard(card("To keep using your OpenKey account, agree to the updated Terms of Service."), terms.embedCard.hrefs, terms.embedCard).textMatches, false);
  assert.equal(judgeTermsCard(card(undefined, ["What changed: the arbitration clause"]), terms.embedCard.hrefs, terms.embedCard).ok, false);
  assert.equal(judgeTermsCard(card(), ["https://tinycloud.xyz/terms", "https://example.com/privacy"], terms.embedCard).hrefsMatch, false);
});
