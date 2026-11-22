// OpenKey embed gate (pre-release). One run = one fresh QA account, driven through the real host
// page (https://tinycloud.one by default) against the OpenKey web under test and the PRODUCTION API.
//
//   EMBED_GATE_TARGET=candidate   openkey.so is the candidate build, served inside the runner
//                                 (wrangler pages dev, TLS) and reached through Chromium's
//                                 --host-resolver-rules + an SPKI pin; api.openkey.so stays production.
//   EMBED_GATE_TARGET=production  the live https://openkey.so (calibration / post-deploy check).
//
// Legs (in order; each needs the previous one):
//   embed-new     host page -> Sign in -> OpenKey connect frame -> email code -> Create a new account
//                 -> every sign review approved -> host signed in. Records the Terms state.
//   terms-owing   the embed-new run when the new account OWED the Terms (GET /api/account/terms says
//                 requiresAcceptance): the frame must stay on /widget/embed/* and show the framed notice.
//                 Terms not owed (Terms off) = UNVERIFIED, never PASS.
//   own-window    https://openkey.so/auth/login in its own window: email code -> passkey created by a
//                 virtual authenticator made in this run (no stored key) -> dashboard.
//   embed-passkey a new browser profile: host page -> Sign in -> Passkey -> sign reviews -> signed in, as
//                 the same account (the agreed account: it has been through the Terms if they are on).
//   popup         a local host page uses @openkey/sdk in popup mode; the pop-up signs in with the passkey.
//   own-passkey   https://openkey.so/auth/login in its own window with the passkey -> dashboard.
//   cleanup       the account is deleted (dashboard/settings/delete-account). Runs even when a leg failed.
//
// Gate rules (fail closed):
//   - every OpenKey document loaded in a frame of the host page is under /widget/embed/; a frame that
//     goes anywhere else, or is refused (frame-ancestors / X-Frame-Options), fails the run;
//   - a sign review is approved only when its face matches an entry of expected-screens.json exactly;
//     anything else on screen (an unknown screen, an extra warning, an alert) fails the run;
//   - a first-party 5xx or 429, or a 403 that is not one of the expected refusals below, stops the run
//     and captures the context.
// Nothing here prints an address, a code, a key or a token; the report and text artifacts are scrubbed, and
// screenshots mask every input and the run's QA mail address (this repository's artifacts are public).
import { chromium } from "@playwright/test";
import { createServer } from "node:http";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInbox, deleteInboxes, deleteInboxesOnStop, openKeyCode, reopenInbox, waitForMail } from "./qa-mail.mjs";
import { judgeSignFace, scrub } from "./judge.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const OPENKEY = "https://openkey.so";
const API = "https://api.openkey.so";
const HOST = process.env.EMBED_GATE_HOST_ORIGIN ?? "https://tinycloud.one";
const TARGET = process.env.EMBED_GATE_TARGET ?? "candidate";
const OUT = process.env.EMBED_GATE_OUT ?? join(process.cwd(), "embed-gate-out");
// Fixed: openkey's QA_MAIL_READ_TOKEN reads only `share-` run ids, and a cleanup run may act only on this label's addresses.
const LABEL = "share-okgate";
const DRY = process.env.EMBED_GATE_DRY === "1"; // stops at the connect frame: no mail, no account
// Cleanup only: deletes the account an earlier run with this 12-hex run id left behind, then reads back that the
// address has no account. No new account is made.
const CLEANUP_RUN_ID = process.env.EMBED_GATE_CLEANUP_RUN_ID ?? "";
const EXPECTED = JSON.parse(readFileSync(process.env.EMBED_GATE_EXPECTED ?? join(HERE, "expected-screens.json"), "utf8"));
const SDK_BUNDLE = process.env.EMBED_GATE_SDK ?? join(HERE, "../../packages/sdk/dist/index.mjs");
const MAX_APPROVALS = 4;

const FIRST_PARTY = /(^|\.)(openkey\.so|tinycloud\.one|tinycloud\.chat|tinycloud\.xyz)$/;
// The refusals a fresh account meets on the way (403 with this machine code at this path); any other
// first-party 403 stops the run. `owing` ones are expected only while the account owes the Terms.
const EXPECTED_403 = [
  { host: "api.openkey.so", path: /^\/api\/auth\/sign-in\/email-otp$/, code: "NEW_ACCOUNT_CONFIRMATION_REQUIRED" },
  { host: "api.openkey.so", path: /^\/api\/auth\/passkey\/generate-register-options$/, code: "PASSKEY_STEP_UP_REQUIRED" },
  { host: "api.openkey.so", path: /^\/api\/keys$/, code: "terms_required", owing: true },
];

mkdirSync(OUT, { recursive: true });
const t0 = Date.now();
const since = () => Date.now() - t0;
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const report = {
  type: "openkey/embed-gate/v1", target: TARGET, host: HOST, startedAt: new Date(t0).toISOString(),
  candidate: TARGET === "candidate" ? { sha: process.env.EMBED_GATE_SHA ?? null, port: Number(process.env.EMBED_GATE_CANDIDATE_PORT) } : null,
  result: "failed", failure: null, legs: {}, terms: { observed: [], owed: null, source: null },
  frames: [], refusedFrames: [], network: [], approvals: [], passkey: { registered: 0, asserted: 0 }, account: { created: false, deleted: null },
};
const save = () => writeFileSync(join(OUT, "report.json"), JSON.stringify(report, null, 2));
const artifact = (name, value) => writeFileSync(join(OUT, name), typeof value === "string" ? scrub(value) : JSON.stringify(value, null, 2));
const runIdOf = (address) => /^tcqa\+[a-z0-9-]+-([0-9a-f]{12})-[0-9a-f]{8}@/.exec(address)?.[1] ?? "unknown";
// The cleanup ledger (artifact cleanup-ledger.json, uploaded even when the job fails or is cancelled): this
// run's QA account by label and run id, written before sign-up. Neither it nor the log holds the address, a hash
// of it or a code: QA_MAIL_ADDRESS_SECRET rebuilds the address from the run id (dispatch cleanup_run_id).
const writeLedger = (state) => {
  const entry = { label: LABEL, runId: runIdOf(inbox.address), state,
    githubRunId: process.env.GITHUB_RUN_ID ?? null, sha: process.env.EMBED_GATE_SHA ?? null, at: new Date().toISOString() };
  writeFileSync(join(OUT, "cleanup-ledger.json"), JSON.stringify(entry, null, 2));
  process.stderr.write(`embed-gate ledger: ${state} label ${entry.label} run id ${entry.runId}\n`);
};
let shots = 0;
const snap = async (page, name) => {
  const mask = page.frames().flatMap((frame) => [frame.locator("input"), frame.getByText(/qa-mail\.tinycloud\.xyz/)]);
  try { await page.screenshot({ path: join(OUT, `${String(++shots).padStart(2, "0")}-${name}.png`), fullPage: false, timeout: 10_000, mask }); } catch {}
};

class GateFailure extends Error {
  constructor(verdict, detail = {}) { super(verdict); this.verdict = verdict; this.detail = detail; }
}
let stopped = null; // set by a watcher (network / frame guard); every wait checks it
const fail = (verdict, detail) => { stopped ??= new GateFailure(verdict, detail); throw stopped; };
const check = () => { if (stopped) throw stopped; };

const leg = (name, status, detail = {}) => { report.legs[name] = { status, atMs: since(), ...detail }; save(); };

/** Polls `probe` until it returns a truthy value; a watcher's stop ends the wait at once. */
async function until(what, probe, timeout = 30_000, poll = 250) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    check();
    let value;
    try { value = await probe(); } catch { value = undefined; }
    if (value) return value;
    await sleep(poll);
  }
  check();
  throw new GateFailure(`timeout:${what}`);
}

/** The first screen in `screens` ([name, locator]) that is visible, or a fail-closed failure with the page captured. */
async function screen(page, what, screens, timeout = 45_000, frame = page) {
  try {
    return await until(what, async () => {
      // A screen is a locator, or a probe for what no locator shows (e.g. the frame navigated to the sign page).
      for (const [name, locator] of screens) {
        const shown = await Promise.resolve().then(() => (typeof locator === "function" ? locator() : locator.first().isVisible())).catch(() => false);
        if (shown) return name;
      }
      return undefined;
    }, timeout, 300);
  } catch (error) {
    if (!(error instanceof GateFailure) || error.verdict !== `timeout:${what}`) throw error;
    await snap(page, `unknown-${what}`);
    artifact(`unknown-${what}.txt`, await frame.locator("body").innerText({ timeout: 3000 }).catch(() => "<unreadable>"));
    throw new GateFailure(`unknown_screen:${what}`, { expected: screens.map(([name]) => name) });
  }
}

const isOpenKey = (url) => { try { return new URL(url).hostname === "openkey.so"; } catch { return false; } };
const pathOf = (url) => { try { return new URL(url).pathname; } catch { return ""; } };

// ---- watchers --------------------------------------------------------------------------------------

function watchNetwork(context, label) {
  context.on("response", async (response) => {
    let url;
    try { url = new URL(response.url()); } catch { return; }
    if (!FIRST_PARTY.test(url.hostname)) return;
    const status = response.status();
    if (url.hostname === "api.openkey.so" && url.pathname === "/api/auth/passkey/verify-registration" && status === 200) report.passkey.verifiedRegistration = true;
    if (url.hostname === "api.openkey.so" && url.pathname === "/api/account/terms" && status === 200) {
      const body = await response.json().catch(() => null);
      if (body && typeof body === "object") report.terms.observed.push({ label, atMs: since(), version: body.version ?? null, requiresAcceptance: body.requiresAcceptance ?? null });
    }
    if (status < 400 || status === 401 || status === 404) return;
    const entry = { label, atMs: since(), method: response.request().method(), host: url.hostname, path: scrub(url.pathname), status };
    if (status === 403) {
      const body = await response.json().catch(() => null);
      const code = body?.code ?? body?.error?.code ?? (typeof body?.error === "string" ? body.error : undefined);
      entry.code = code === undefined ? undefined : scrub(String(code)).slice(0, 80);
      const known = EXPECTED_403.find((rule) => rule.host === url.hostname && rule.path.test(url.pathname) && rule.code === code);
      if (known?.owing) report.terms.refusedForTerms = true;
      if (known) { entry.expected = true; report.network.push(entry); return; }
    }
    report.network.push(entry);
    if (status >= 500 || status === 429 || status === 403) {
      stopped ??= new GateFailure(`first_party_${status}`, entry);
    }
  });
}

/** Every OpenKey document a host page loads in a frame must be under /widget/embed/. */
function guardFrames(page, label) {
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame()) return;
    const url = frame.url();
    if (url.startsWith("chrome-error://")) {
      report.refusedFrames.push({ label, atMs: since(), url });
      stopped ??= new GateFailure("frame_refused", { label, url });
      return;
    }
    if (!isOpenKey(url)) return;
    const path = pathOf(url);
    report.frames.push({ label, atMs: since(), path });
    if (!path.startsWith("/widget/embed/")) stopped ??= new GateFailure("frame_left_widget_embed", { label, path });
  });
  page.on("console", (message) => {
    const text = message.text();
    if (/Refused to (frame|display)/i.test(text) && /openkey\.so/.test(text)) {
      report.refusedFrames.push({ label, atMs: since(), console: scrub(text).slice(0, 240) });
      stopped ??= new GateFailure("frame_refused", { label });
    }
  });
}

/** The address OpenKey hands the host page (openkey:auth:response), for the same-account checks. */
async function recordAuthResponses(page, sink) {
  await page.exposeFunction("__embedGateAuth", (address) => { if (typeof address === "string") sink.push(address.toLowerCase()); });
  await page.addInitScript(() => {
    window.addEventListener("message", (event) => {
      if (event.origin === "https://openkey.so" && event.data?.type === "openkey:auth:response" && event.data.success === true) void window.__embedGateAuth(event.data.address);
    });
  });
}

// ---- virtual passkey -------------------------------------------------------------------------------

let credentials = []; // in memory only: the passkey this run registered
let highestSignCount = 0;
const nextSignCount = () => Math.max(highestSignCount + 1, Math.floor(Date.now() / 1000));

/** A CDP virtual authenticator on a page or an out-of-process frame, holding this run's passkey. */
async function authenticator(context, target, label) {
  const client = await context.newCDPSession(target);
  await client.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  for (const credential of credentials) await client.send("WebAuthn.addCredential", { authenticatorId, credential: { ...credential, signCount: nextSignCount() } });
  const state = { client, authenticatorId, asserted: 0 };
  client.on("WebAuthn.credentialAsserted", (event) => {
    state.asserted += 1;
    report.passkey.asserted += 1;
    highestSignCount = Math.max(highestSignCount, event.credential?.signCount ?? 0);
    report.passkey.assertions = [...(report.passkey.assertions ?? []), { label, atMs: since() }];
  });
  return state;
}

// ---- host page (tinycloud.one) ---------------------------------------------------------------------

async function closeHostDialogs(page) {
  for (let i = 0; i < 3; i++) {
    const close = page.locator("[data-desktop-close]:visible").first();
    if (!(await close.count().catch(() => 0))) return;
    await close.click({ timeout: 5000 }).catch(() => {});
    await sleep(300);
  }
}

const frameAt = (page, path) => page.frames().find((frame) => isOpenKey(frame.url()) && pathOf(frame.url()) === path);

async function hostSignIn(page, label) {
  await page.goto(`${HOST}/`, { waitUntil: "domcontentloaded", timeout: 60_000 });
  const signIn = page.getByRole("button", { name: EXPECTED.host.signInButton, exact: true });
  await until(`${label}-host-signed-out`, () => signIn.first().isVisible(), 45_000);
  await closeHostDialogs(page);
  await snap(page, `${label}-host-signed-out`);
  await signIn.first().click({ timeout: 15_000 });
  const connect = await until(`${label}-connect-frame`, () => frameAt(page, "/widget/embed/connect"), 30_000);
  await snap(page, `${label}-connect-frame`);
  return connect;
}

const button = (frame, text) => frame.getByRole("button", { name: new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`) });

/**
 * Approves sign reviews in the host page until it is signed in. Each review's face must match an
 * expected screen exactly; an approval needs the button to be ready and the click to be taken.
 */
async function approveUntilSignedIn(page, context, label, { passkeyFrames = false } = {}) {
  const signedIn = async () => {
    if (await page.getByRole("button", { name: EXPECTED.host.signInButton, exact: true }).count() > 0) return false;
    for (const name of EXPECTED.host.signedInMarkers) {
      // The signed-in navigation (Home, Chat, You); by role where it has one, else by its text.
      const marker = page.getByRole("link", { name, exact: true }).or(page.getByRole("button", { name, exact: true })).or(page.getByText(name, { exact: true }));
      if (!(await marker.first().isVisible().catch(() => false))) return false;
    }
    return !frameAt(page, "/widget/embed/sign");
  };
  const withAuthenticator = new WeakSet();
  let keyPicks = 0;
  const deadline = Date.now() + 240_000;
  let approvals = 0;
  while (Date.now() < deadline) {
    check();
    if (await signedIn().catch(() => false)) return approvals;
    // A returning account's connect frame may ask which key to connect: the primary key is the expected answer.
    const connect = frameAt(page, "/widget/embed/connect");
    if (connect && keyPicks === 0 && await connect.getByText("Connect with your primary key:", { exact: true }).isVisible().catch(() => false)) {
      const primary = connect.locator("button[aria-pressed]").filter({ hasText: "Primary" });
      if (await primary.count() !== 1) fail("key_picker_without_one_primary_key", { label });
      await snap(page, `${label}-key-picker`);
      await primary.click({ timeout: 10_000 });
      keyPicks += 1;
      report.keyPicks = [...(report.keyPicks ?? []), { label, atMs: since() }];
    }
    const sign = frameAt(page, "/widget/embed/sign");
    if (sign) {
      const dialog = sign.locator('.signing-approval[role="dialog"]');
      const approve = dialog.getByRole("button", { name: "Approve", exact: true });
      const ready = await approve.isEnabled({ timeout: 1000 }).catch(() => false);
      const elevated = await sign.locator('.elevated[role="dialog"]').count().catch(() => 0);
      if (elevated) {
        await snap(page, `${label}-elevated`);
        artifact(`${label}-elevated.txt`, await sign.locator("body").innerText({ timeout: 4000 }).catch(() => ""));
        fail("unexpected_elevated_warning", { label });
      }
      if (ready) {
        // The verified browser origin is inside the folded "Advanced details"; open it as a reader would.
        const details = dialog.locator("details").filter({ has: sign.locator("summary", { hasText: /^Advanced details$/ }) }).first();
        if (await details.count() && !(await details.evaluate((element) => element.open).catch(() => true))) {
          await details.locator("summary").first().click({ timeout: 5000 });
          await until(`${label}-advanced-details-open`, () => details.evaluate((element) => element.open), 5000);
        }
        const text = await sign.locator("body").innerText({ timeout: 5000 }).catch(() => "");
        const verdict = judgeSignFace(text, EXPECTED.signFaces, { hostOrigin: HOST });
        artifact(`${label}-sign-${approvals + 1}.txt`, text);
        await snap(page, `${label}-sign-${approvals + 1}`);
        if (!verdict.ok) fail("sign_face_not_expected", { label, review: approvals + 1, ...verdict });
        if (approvals >= MAX_APPROVALS) fail("too_many_approvals", { label, approvals });
        if (passkeyFrames && !withAuthenticator.has(sign)) {
          withAuthenticator.add(sign);
          await authenticator(context, sign, `${label}-sign-${approvals + 1}`);
        }
        await approve.click({ timeout: 10_000 });
        approvals += 1;
        report.approvals.push({ label, atMs: since(), face: verdict.face });
        save();
        // Taken = the review closed, or its Approve button is no longer offered (Signing…, the next review).
        await until(`${label}-review-${approvals}-taken`, async () => sign.isDetached() || frameAt(page, "/widget/embed/sign") !== sign
          || !(await approve.isEnabled({ timeout: 300 }).catch(() => false)), 60_000);
        await sleep(1000);
      }
    }
    for (const frame of page.frames().filter((candidate) => isOpenKey(candidate.url()))) {
      const alert = await frame.locator('[role="alert"]:visible').first().innerText({ timeout: 500 }).catch(() => "");
      if (alert.trim()) {
        await snap(page, `${label}-openkey-alert`);
        fail("openkey_alert", { label, path: pathOf(frame.url()), text: scrub(alert).slice(0, 200) });
      }
    }
    await sleep(300);
  }
  await snap(page, `${label}-not-signed-in`);
  artifact(`${label}-not-signed-in.txt`, await page.locator("body").innerText({ timeout: 3000 }).catch(() => ""));
  throw new GateFailure("host_not_signed_in", { label, approvals });
}

// ---- OpenKey own window ----------------------------------------------------------------------------

const usedMail = new Set();
const code = () => openKeyCode(inbox, { used: usedMail, timeout: 150_000 });
// Step-up codes (add a passkey, delete the account) come in another template: "Use this code to …:" then the code
// (apps/api/src/services/email-otp-step-up.ts EMAILS).
const stepUpCodeIn = (text) => {
  const codes = new Set([...text.matchAll(/Use this code to [^0-9]{0,160}?(\d{6})(?!\d)/gi)].map((match) => match[1]));
  return codes.size === 1 ? [...codes][0] : undefined;
};
const stepUpCode = (subject) => waitForMail(inbox, { subject, extract: stepUpCodeIn, used: usedMail, timeout: 150_000, failure: "no OpenKey step-up code arrived in the test inbox" });

// Better Auth's email-OTP routes allow 3 calls per 60 s per client, and the count only resets after 60 s with
// none (node_modules/better-auth/dist/plugins/email-otp/index.mjs:75-103). PR run 45012700587 met that 429 on
// its second sign-in code. Every sign-in code request waits until 61 s have passed since the last one.
let lastOtpRequest = 0;
async function paceOtp(label) {
  const wait = lastOtpRequest + 61_000 - Date.now();
  if (wait > 0) {
    report.otpPacing = [...(report.otpPacing ?? []), { label, waitedMs: wait }];
    await sleep(wait);
  }
  check();
  lastOtpRequest = Date.now();
}

/**
 * Cleanup and read-back only: on a first-party 429, wait once for 61 s with no calls, then try once more
 * (Clarissa, 10:36Z). Each attempt starts with no stop recorded; its own watcher records any refusal.
 */
async function onceMoreAfter429(label, attempt) {
  stopped = null;
  try {
    return await attempt();
  } catch (error) {
    const verdict = error instanceof GateFailure ? error.verdict : stopped?.verdict;
    if (verdict !== "first_party_429") throw error;
    report.retriedAfter429 = [...(report.retriedAfter429 ?? []), { label, atMs: since() }];
    await sleep(61_000);
    lastOtpRequest = Date.now() - 61_000;
    stopped = null;
    return attempt();
  }
}

/** Email sign-in on https://openkey.so/auth/login in its own window; returns the screen it lands on. */
async function ownWindowEmailSignIn(page, redirect) {
  await page.goto(`${OPENKEY}/auth/login${redirect ? `?redirect=${encodeURIComponent(redirect)}` : ""}`, { waitUntil: "domcontentloaded", timeout: 60_000 });
  const email = page.locator('input[type="email"]').first();
  await until("own-window-email-field", () => email.isVisible(), 30_000);
  await email.fill(inbox.address);
  await paceOtp("own-window");
  await page.getByRole("button", { name: "Continue with email", exact: true }).click({ timeout: 10_000 });
  await screen(page, "own-window-check-email", [["otp", page.locator("input#otp")]], 30_000);
  await page.locator("input#otp").fill(await code());
  await page.getByRole("button", { name: /^Verify and continue$/ }).click({ timeout: 10_000 });
  return screen(page, "own-window-after-code", [
    ["new-account", page.getByRole("button", { name: "Create a new account", exact: true })],
    ["terms", page.getByRole("button", { name: "Agree and continue", exact: true })],
    ["secure", page.getByRole("heading", { name: "Secure your account", exact: true })],
    ["dashboard", page.getByRole("heading", { name: "Your Keys", exact: true })],
    ["delete-account", page.getByRole("heading", { name: /^Delete (your OpenKey )?account$/ })],
  ], 45_000);
}

/** The step-up dialog an add-passkey meets with a session alone: an email code, then the retry. */
async function stepUpByEmail(page) {
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Email me a code", exact: true }).click({ timeout: 10_000 });
  await dialog.locator("#passkey-step-up-code").fill(await stepUpCode(/add a passkey to your OpenKey account/));
  await dialog.getByRole("button", { name: "Verify code", exact: true }).click({ timeout: 10_000 });
}

async function registerPasskey(page, context) {
  const auth = await authenticator(context, page, "own-window-register");
  const before = since();
  let landed = await screen(page, "own-window-before-passkey", [
    ["terms", page.getByRole("button", { name: "Agree and continue", exact: true })],
    ["secure", page.getByRole("heading", { name: "Secure your account", exact: true })],
    ["dashboard", page.getByRole("heading", { name: "Your Keys", exact: true })],
  ], 30_000);
  if (landed === "terms") {
    report.terms.agreedIn = "own-window";
    await page.getByRole("button", { name: "Agree and continue", exact: true }).click({ timeout: 10_000 });
    landed = await screen(page, "own-window-after-terms", [
      ["secure", page.getByRole("heading", { name: "Secure your account", exact: true })],
      ["dashboard", page.getByRole("heading", { name: "Your Keys", exact: true })],
    ], 30_000);
  }
  if (landed === "secure") {
    await page.getByRole("button", { name: "Create a passkey", exact: true }).click({ timeout: 10_000 });
  } else {
    await page.goto(`${OPENKEY}/dashboard/settings`, { waitUntil: "domcontentloaded", timeout: 60_000 });
    await page.getByRole("button", { name: "+ Add Passkey", exact: true }).click({ timeout: 30_000 });
  }
  // Done when the API accepted the registration; an add with a session alone first meets the step-up dialog.
  let steppedUp = false;
  await until("own-window-passkey-registered", async () => {
    if (report.passkey.verifiedRegistration) return true;
    if (!steppedUp && await page.getByRole("button", { name: "Email me a code", exact: true }).isVisible().catch(() => false)) {
      steppedUp = true;
      report.passkey.stepUp = "email";
      await stepUpByEmail(page);
    }
    const alert = await page.locator('[role="alert"]:visible').first().innerText({ timeout: 300 }).catch(() => "");
    if (alert.trim()) { await snap(page, "own-window-passkey-alert"); fail("own_window_passkey_alert", { text: scrub(alert).slice(0, 200) }); }
    return false;
  }, 120_000, 400);
  const { credentials: made } = await auth.client.send("WebAuthn.getCredentials", { authenticatorId: auth.authenticatorId });
  if (made.length !== 1) fail("virtual_authenticator_holds_unexpected_credentials", { count: made.length });
  credentials = made.map(({ credentialId, isResidentCredential, rpId, privateKey, userHandle }) => ({ credentialId, isResidentCredential, rpId, privateKey, userHandle }));
  highestSignCount = Math.max(highestSignCount, made[0].signCount ?? 0);
  if (credentials[0].rpId !== "openkey.so") fail("passkey_rp_id_unexpected", { rpId: credentials[0].rpId });
  report.passkey.registered = 1;
  report.passkey.registeredAfterMs = since() - before;
}

/** Deletes the run's account in its own window: passkey when the account has one, else an email code. */
async function deleteAccount(browser) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: "block" });
  watchNetwork(context, "cleanup");
  const page = await context.newPage();
  try {
    if (credentials.length) await authenticator(context, page, "cleanup");
    await page.goto(`${OPENKEY}/dashboard/settings/delete-account`, { waitUntil: "domcontentloaded", timeout: 60_000 });
    let landed = await screen(page, "cleanup-start", [
      ["explain", page.getByRole("heading", { name: "Delete your OpenKey account", exact: true })],
      ["login", page.locator('input[type="email"]')],
    ], 45_000);
    if (landed === "login") {
      landed = await ownWindowEmailSignIn(page, "/dashboard/settings/delete-account");
      if (landed === "new-account") return { deleted: false, reason: "no_account" };
      if (landed === "terms") await page.getByRole("button", { name: "Agree and continue", exact: true }).click({ timeout: 10_000 });
      if (landed === "secure") await page.getByRole("button", { name: "Skip for now", exact: true }).click({ timeout: 10_000 });
      await screen(page, "cleanup-explain", [["explain", page.getByRole("heading", { name: "Delete your OpenKey account", exact: true })]], 45_000);
    }
    await page.getByRole("button", { name: "Continue", exact: true }).click({ timeout: 10_000 });
    await page.locator("#delete-confirmation").fill(EXPECTED.deleteConfirmation);
    await page.getByRole("button", { name: "Continue", exact: true }).click({ timeout: 10_000 });
    const method = await screen(page, "cleanup-verify", [
      ["passkey", page.getByRole("button", { name: "Verify with passkey and delete", exact: true })],
      ["email", page.getByRole("button", { name: "Send code", exact: true })],
    ], 30_000);
    if (method === "passkey") {
      await page.getByRole("button", { name: "Verify with passkey and delete", exact: true }).click({ timeout: 10_000 });
    } else {
      await page.getByRole("button", { name: "Send code", exact: true }).click({ timeout: 10_000 });
      await page.locator("#delete-code").fill(await stepUpCode(/delete your OpenKey account/));
      await page.getByRole("button", { name: "Verify and delete account", exact: true }).click({ timeout: 10_000 });
    }
    await screen(page, "cleanup-done", [["done", page.getByRole("heading", { name: "Your account was deleted", exact: true })]], 45_000);
    await snap(page, "cleanup-deleted");
    return { deleted: true, method };
  } finally {
    await context.close().catch(() => {});
  }
}

/** After a delete: true when the address signs in as a stranger (OpenKey offers "Create a new account", never pressed). */
async function readBackGone(browser) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: "block" });
  watchNetwork(context, "read-back");
  const page = await context.newPage();
  try {
    const landed = await ownWindowEmailSignIn(page);
    await snap(page, "read-back");
    return landed === "new-account";
  } finally {
    await context.close().catch(() => {});
  }
}

// ---- pop-up host page (local) ----------------------------------------------------------------------

function startPopupHost() {
  const sdk = readFileSync(SDK_BUNDLE);
  const html = `<!doctype html><meta charset="utf-8"><title>OpenKey embed gate pop-up host</title>
<button id="connect" type="button">Connect with OpenKey</button><pre id="result"></pre>
<script type="module">
import { OpenKey } from "/sdk.mjs";
const openkey = new OpenKey({ host: "${OPENKEY}", mode: "popup", appName: "OpenKey embed gate" });
document.getElementById("connect").addEventListener("click", () => {
  openkey.connect({ mode: "popup" }).then(
    (result) => { window.__gateResult = { ok: true, address: String(result?.address ?? "").toLowerCase() }; },
    (error) => { window.__gateResult = { ok: false, code: String(error?.code ?? error?.name ?? "error") }; });
});
</script>`;
  const server = createServer((request, response) => {
    if (request.url === "/sdk.mjs") { response.writeHead(200, { "content-type": "text/javascript" }); response.end(sdk); return; }
    if (request.url === "/" || request.url?.startsWith("/?")) { response.writeHead(200, { "content-type": "text/html; charset=utf-8" }); response.end(html); return; }
    response.writeHead(404); response.end();
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, origin: `http://localhost:${server.address().port}` })));
}

// ---- run -------------------------------------------------------------------------------------------

let inbox;
deleteInboxesOnStop({ before: () => { report.failure ??= { verdict: "stopped_by_signal" }; save(); } });

const launchArgs = [];
if (TARGET === "candidate") {
  const port = Number(process.env.EMBED_GATE_CANDIDATE_PORT);
  const spki = process.env.EMBED_GATE_CANDIDATE_SPKI ?? "";
  if (!port || !/^[A-Za-z0-9+/]{43}=$/.test(spki)) throw new Error("candidate target needs EMBED_GATE_CANDIDATE_PORT and EMBED_GATE_CANDIDATE_SPKI");
  // Only openkey.so is mapped: api.openkey.so and every other host stay production. The candidate answers
  // on 127.0.0.1, so Chrome's Local Network Access checks would refuse it inside the public host page
  // (net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS); they are off in this runner's browser only.
  launchArgs.push(`--host-resolver-rules=MAP openkey.so 127.0.0.1:${port}`, `--ignore-certificate-errors-spki-list=${spki}`,
    "--disable-features=LocalNetworkAccessChecks,BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights");
}
const browser = await chromium.launch({ headless: true, args: launchArgs });
const addresses = { embedNew: [], embedPasskey: [], popup: null };
let accountMayExist = false;

try {
  if (CLEANUP_RUN_ID) {
    inbox = reopenInbox(LABEL, CLEANUP_RUN_ID);
    accountMayExist = true;
    report.mode = "cleanup-only";
    throw new GateFailure("cleanup_only");
  }
  // embed-new (+ terms-owing) ------------------------------------------------------------------------
  {
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: "block" });
    watchNetwork(context, "embed-new");
    const page = await context.newPage();
    guardFrames(page, "embed-new");
    await recordAuthResponses(page, addresses.embedNew);
    const connect = await hostSignIn(page, "embed-new");
    await until("connect-email-option", () => button(connect, "Continue with email").first().isVisible(), 30_000);
    if (DRY) {
      report.dry = { connectFrame: true, passkeyButton: await connect.getByRole("button", { name: "Passkey", exact: true }).isVisible().catch(() => false) };
      leg("embed-new", "DRY", report.dry);
      throw new GateFailure("dry_run_stop");
    }
    inbox = createInbox(LABEL);
    // The ledger holds this run's account before OpenKey can make it, so a crash or a killed runner never loses it.
    writeLedger("signing-up");
    await button(connect, "Continue with email").first().click({ timeout: 10_000 });
    await until("connect-email-field", () => connect.locator('input[type="email"]').isVisible(), 30_000);
    await connect.locator('input[type="email"]').fill(inbox.address);
    await paceOtp("embed-new");
    await button(connect, "Send code").first().click({ timeout: 10_000 });
    const codeField = connect.locator('input[autocomplete="one-time-code"], input[inputmode="numeric"], input[type="text"]').first();
    await until("connect-code-field", () => codeField.isVisible(), 30_000);
    await codeField.fill(await code());
    await button(connect, "Verify").first().click({ timeout: 10_000 });
    const landed = await screen(page, "connect-after-code", [
      ["new-account", connect.getByRole("button", { name: "Create a new account", exact: true })],
      ["sign", () => Boolean(frameAt(page, "/widget/embed/sign"))],
    ], 45_000, connect);
    if (landed !== "new-account") fail("fresh_address_was_not_asked_to_create_an_account");
    await connect.getByRole("button", { name: "Create a new account", exact: true }).click({ timeout: 10_000 });
    accountMayExist = true;
    report.account.created = true;
    // A new account that owes the Terms meets the framed notice (#685) and agrees in a window of its own.
    const next = await screen(page, "connect-after-create", [
      ["terms-notice", connect.getByRole("heading", { name: EXPECTED.terms.framedNoticeHeading, exact: true })],
      ["sign", () => Boolean(frameAt(page, "/widget/embed/sign"))],
    ], 60_000, connect);
    if (next === "terms-notice") {
      report.terms.framedNotice = true;
      await snap(page, "embed-new-terms-notice");
      const opened = context.waitForEvent("page", { timeout: 30_000 });
      await connect.getByRole("button", { name: EXPECTED.terms.openButton, exact: true }).click({ timeout: 10_000 });
      const terms = await opened;
      await terms.waitForLoadState("domcontentloaded");
      const termsScreen = await screen(terms, "terms-window", [["agree", terms.getByRole("button", { name: "Agree and continue", exact: true })]], 45_000);
      report.terms.window = { path: pathOf(terms.url()), screen: termsScreen };
      await terms.getByRole("button", { name: "Agree and continue", exact: true }).click({ timeout: 10_000 });
      report.terms.agreedIn = "terms-window";
    }
    const approvals = await approveUntilSignedIn(page, context, "embed-new");
    await snap(page, "embed-new-signed-in");
    if (addresses.embedNew.length === 0) fail("no_openkey_auth_response_on_host", { label: "embed-new" });
    leg("embed-new", "PASS", { approvals, framesSeen: [...new Set(report.frames.filter((f) => f.label === "embed-new").map((f) => f.path))] });
    await context.close();
  }

  // own-window: email sign-in + passkey -------------------------------------------------------------
  {
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: "block" });
    watchNetwork(context, "own-window");
    const page = await context.newPage();
    const landed = await ownWindowEmailSignIn(page);
    if (landed === "new-account") fail("own_window_did_not_know_the_account");
    // The account's own Terms status (read-only), for the terms-owing verdict when the embed did not read it.
    const status = await page.request.get(`${API}/api/account/terms`).catch(() => null);
    const body = status?.ok() ? await status.json().catch(() => null) : null;
    if (body) report.terms.observed.push({ label: "own-window-read", atMs: since(), version: body.version ?? null, requiresAcceptance: body.requiresAcceptance ?? null, previouslyAccepted: body.previouslyAccepted ?? null });
    await registerPasskey(page, context);
    await until("own-window-dashboard", async () => {
      if (await page.getByRole("heading", { name: "Your Keys", exact: true }).isVisible().catch(() => false)) return true;
      if (pathOf(page.url()).startsWith("/dashboard/settings")) return true;
      return false;
    }, 45_000);
    await snap(page, "own-window-passkey-registered");
    leg("own-window", "PASS", { stepUp: report.passkey.stepUp ?? "none" });
    await context.close();
  }

  // terms-owing verdict -----------------------------------------------------------------------------
  {
    const embedRead = report.terms.observed.find((entry) => entry.label === "embed-new");
    const ownRead = report.terms.observed.find((entry) => entry.label === "own-window-read");
    const owed = report.terms.framedNotice === true || report.terms.refusedForTerms === true || embedRead?.requiresAcceptance === true;
    report.terms.owed = owed;
    report.terms.source = embedRead ? "embed GET /api/account/terms" : ownRead ? "own-window GET /api/account/terms" : "not observed";
    if (owed) leg("terms-owing", "PASS", { notice: report.terms.framedNotice === true, agreedIn: report.terms.agreedIn ?? null });
    else leg("terms-owing", "UNVERIFIED", { reason: ownRead?.version === null || embedRead?.version === null ? "terms off (Terms version null)" : "the new account did not owe the Terms", requiresAcceptance: embedRead?.requiresAcceptance ?? ownRead?.requiresAcceptance ?? null });
  }

  // embed-passkey: the agreed account, a new browser profile ------------------------------------------
  {
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: "block" });
    watchNetwork(context, "embed-passkey");
    const page = await context.newPage();
    guardFrames(page, "embed-passkey");
    await recordAuthResponses(page, addresses.embedPasskey);
    const connect = await hostSignIn(page, "embed-passkey");
    const auth = await authenticator(context, connect, "embed-passkey-connect");
    await until("connect-passkey-option", () => connect.getByRole("button", { name: "Passkey", exact: true }).isVisible(), 30_000);
    await connect.getByRole("button", { name: "Passkey", exact: true }).click({ timeout: 10_000 });
    await until("connect-passkey-asserted", () => auth.asserted > 0, 30_000);
    const approvals = await approveUntilSignedIn(page, context, "embed-passkey", { passkeyFrames: true });
    await snap(page, "embed-passkey-signed-in");
    const same = addresses.embedPasskey.length > 0 && addresses.embedPasskey.every((address) => addresses.embedNew.includes(address));
    if (!same) fail("embed_passkey_signed_in_as_another_account");
    leg("embed-passkey", "PASS", { approvals, connectAssertions: auth.asserted });
    await context.close();
  }

  // popup -------------------------------------------------------------------------------------------
  {
    const { server, origin } = await startPopupHost();
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: "block" });
    watchNetwork(context, "popup");
    try {
      const page = await context.newPage();
      await page.goto(`${origin}/`, { waitUntil: "domcontentloaded", timeout: 30_000 });
      const opened = context.waitForEvent("page", { timeout: 30_000 });
      await page.locator("#connect").click({ timeout: 10_000 });
      const popup = await opened;
      const paths = [];
      popup.on("framenavigated", (frame) => { if (frame === popup.mainFrame() && isOpenKey(frame.url())) paths.push(pathOf(frame.url())); });
      // The SDK opens the window inside the click, then sends it to OpenKey once it knows the URL.
      await until("popup-at-openkey", () => isOpenKey(popup.url()), 30_000)
        .catch(() => fail("popup_not_openkey", { url: scrub(popup.url()).slice(0, 120) }));
      await popup.waitForLoadState("domcontentloaded");
      paths.push(pathOf(popup.url()));
      const auth = await authenticator(context, popup, "popup");
      await until("popup-passkey-option", () => popup.getByRole("button", { name: EXPECTED.popup.passkeyButton, exact: true }).isVisible(), 30_000)
        .catch(async (error) => { await snap(popup, "popup-no-passkey"); artifact("popup-screen.txt", await popup.locator("body").innerText({ timeout: 3000 }).catch(() => "")); throw error; });
      await popup.getByRole("button", { name: EXPECTED.popup.passkeyButton, exact: true }).click({ timeout: 10_000 });
      // Signed in, the pop-up asks which key to connect (KeyPicker); the primary key is the expected answer.
      let picked = false;
      const result = await until("popup-result", async () => {
        const done = await page.evaluate(() => window.__gateResult);
        if (done) return done;
        if (!picked && !popup.isClosed() && await popup.getByText("Connect with your primary key:", { exact: true }).isVisible().catch(() => false)) {
          const primary = popup.locator("button[aria-pressed]").filter({ hasText: "Primary" });
          if (await primary.count() !== 1) fail("popup_key_picker_without_one_primary_key");
          picked = true;
          await primary.click({ timeout: 10_000 });
        }
        return undefined;
      }, 90_000);
      if (!result.ok) fail("popup_connect_failed", { code: scrub(result.code) });
      if (!addresses.embedNew.includes(result.address)) fail("popup_signed_in_as_another_account");
      leg("popup", "PASS", { paths: [...new Set(paths)], assertions: auth.asserted });
    } finally {
      await context.close().catch(() => {});
      server.close();
    }
  }

  // own-passkey -------------------------------------------------------------------------------------
  {
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: "block" });
    watchNetwork(context, "own-passkey");
    const page = await context.newPage();
    const auth = await authenticator(context, page, "own-passkey");
    await page.goto(`${OPENKEY}/auth/login`, { waitUntil: "domcontentloaded", timeout: 60_000 });
    // The login page may also offer the passkey in the email field (conditional mediation); either way the
    // sign-in must come from this run's passkey (asserted below).
    const first = await screen(page, "own-passkey-login", [
      ["dashboard", page.getByRole("heading", { name: "Your Keys", exact: true })],
      ["passkey-button", page.getByRole("button", { name: /^(Use a passkey instead|Sign in with a passkey)$/ })],
    ], 30_000);
    if (first === "passkey-button") await page.getByRole("button", { name: /^(Use a passkey instead|Sign in with a passkey)$/ }).first().click({ timeout: 10_000 });
    await screen(page, "own-passkey-dashboard", [["dashboard", page.getByRole("heading", { name: "Your Keys", exact: true })]], 45_000);
    if (auth.asserted < 1) fail("own_passkey_signed_in_without_the_passkey");
    await snap(page, "own-passkey-dashboard");
    leg("own-passkey", "PASS", { assertions: auth.asserted });
    await context.close();
  }

  report.result = Object.values(report.legs).every((entry) => entry.status === "PASS" || entry.status === "UNVERIFIED") ? "passed" : "failed";
} catch (error) {
  const failure = error instanceof GateFailure ? error : stopped ?? new GateFailure("error", { message: scrub(String(error?.message ?? error)).split("\n")[0].slice(0, 300) });
  if (failure.verdict === "cleanup_only") {
    report.result = "cleanup";
  } else {
    if (stopped && failure !== stopped) report.failure = { verdict: stopped.verdict, detail: stopped.detail, then: failure.verdict };
    else report.failure = { verdict: failure.verdict, detail: failure.detail };
    report.result = failure.verdict === "dry_run_stop" ? "dry" : "failed";
    for (const page of browser.contexts().flatMap((context) => context.pages())) await snap(page, "failure");
  }
} finally {
  // cleanup -----------------------------------------------------------------------------------------
  if (accountMayExist) {
    try {
      const result = await onceMoreAfter429("cleanup", () => deleteAccount(browser));
      // "no_account": the run stopped before OpenKey created the account; nothing to delete, nothing leaked.
      report.account.deleted = result.deleted || result.reason === "no_account";
      leg("cleanup", report.account.deleted ? "PASS" : "FAIL", result);
    } catch (error) {
      report.account.deleted = false;
      leg("cleanup", "FAIL", { verdict: error instanceof GateFailure ? error.verdict : scrub(String(error?.message ?? error)).slice(0, 200) });
    }
    // A leaked QA account fails the run, whatever the legs said. Its 12-hex run id (never the address) goes in
    // the summary so leaks can be counted and cleaned up (Bobbie, #690 review).
    if (report.account.deleted !== true) {
      report.result = "failed";
      report.account.leakedRunId = inbox ? runIdOf(inbox.address) : "unknown";
    }
    if (inbox) writeLedger(report.account.deleted === true ? "deleted" : "LEAKED");
    if (report.account.deleted === true && report.mode === "cleanup-only") {
      // Read back: the address must now sign in as a stranger ("Create a new account"), which is never pressed.
      try {
        const gone = await onceMoreAfter429("read-back", () => readBackGone(browser));
        leg("read-back", gone ? "PASS" : "FAIL", { noAccount: gone });
        report.result = gone ? "passed" : "failed";
      } catch (error) {
        leg("read-back", "FAIL", { verdict: error instanceof GateFailure ? error.verdict : scrub(String(error?.message ?? error)).slice(0, 200) });
        report.result = "failed";
      }
    }
  }
  if (inbox) report.inboxDeleted = await deleteInboxes().then(({ deleted, total }) => deleted === total).catch(() => false);
  credentials = [];
  await browser.close().catch(() => {});
  report.finishedAt = new Date().toISOString();
  report.durationMs = since();
  save();
  writeFileSync(join(OUT, "summary.md"), summary());
  process.stdout.write(summary());
  process.exitCode = report.result === "passed" || report.result === "dry" ? 0 : 1;
}

function summary() {
  const lines = [`## OpenKey embed gate: ${report.result.toUpperCase()}`, "",
    `Target: ${TARGET}${report.candidate?.sha ? ` (${report.candidate.sha.slice(0, 12)})` : ""}; host page ${HOST}; API ${API}${report.mode ? `; mode ${report.mode} (run id ${CLEANUP_RUN_ID})` : ""}`, ""];
  for (const [name, entry] of Object.entries(report.legs)) {
    const extra = name === "terms-owing" && entry.status === "UNVERIFIED" ? ` (${entry.reason})` : "";
    lines.push(`- ${name}: ${entry.status}${extra}`);
  }
  if (report.failure && report.result !== "dry") lines.push("", `Failure: \`${report.failure.verdict}\`${report.failure.detail ? ` ${JSON.stringify(report.failure.detail).slice(0, 400)}` : ""}`);
  lines.push("", `Terms owed by the new account: ${report.terms.owed === null ? "not decided" : report.terms.owed} (${report.terms.source ?? "n/a"})`,
    `OpenKey frame paths: ${[...new Set(report.frames.map((f) => f.path))].join(", ") || "none"}`,
    `Refused frames: ${report.refusedFrames.length}; approvals: ${report.approvals.length}; passkey assertions: ${report.passkey.asserted}`,
    `QA account deleted: ${report.account.deleted ?? "n/a"}${report.account.leakedRunId ? ` (LEAKED: run id ${report.account.leakedRunId})` : ""}; duration ${Math.round(since() / 1000)} s`, "");
  return lines.join("\n");
}
