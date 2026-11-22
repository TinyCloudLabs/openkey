// The embed gate's expected-screen judge for an OpenKey sign review, and the artifact scrubber.
// A review is approved only when its face matches one entry of expected-screens.json exactly:
//   - the title lines and "Requested by <host page's hostname>";
//   - the permission lines between the review's intro and its first note/"Advanced details", as a
//     multiset equal to the entry's `permissions` (no extra line, no missing line);
//   - every other line in that region matches one of the entry's `notes` patterns (the expiry line);
//   - "Verified browser origin" is followed by the host page's origin;
//   - none of the `forbidden` texts appears anywhere in the frame.
// Anything else fails closed with the reason and the lines that differ.

/** Removes addresses, emails, DIDs, codes and tokens from text kept in artifacts. */
export function scrub(text) {
  return String(text)
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "<email>")
    .replace(/did:[a-z0-9]+:[A-Za-z0-9:._%-]+/g, "<did>")
    .replace(/tinycloud:pkh:[A-Za-z0-9:._-]+/g, "<space>")
    .replace(/0x[0-9a-fA-F]{40}\b/g, "<address>")
    .replace(/\b[0-9a-fA-F]{64}\b/g, "<hex64>")
    .replace(/\b\d{6}\b/g, "<6digits>")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1<token>");
}

const lineList = (text) => String(text).split("\n").map((line) => line.trim()).filter(Boolean);

/**
 * Judges the visible text of a sign review frame against the expected faces.
 * Returns { ok: true, face } or { ok: false, reason, ... }.
 */
export function judgeSignFace(text, faces, { hostOrigin }) {
  const hostname = new URL(hostOrigin).hostname;
  const lines = lineList(text).filter((line) => line !== "Scroll to approve");
  const results = [];
  for (const face of faces) {
    const forbidden = (face.forbidden ?? []).filter((needle) => String(text).includes(needle));
    if (forbidden.length) { results.push({ face: face.name, reason: "forbidden_text", forbidden }); continue; }
    const titleAt = lines.indexOf(face.title[0]);
    if (titleAt < 0 || face.title.some((title, i) => lines[titleAt + i] !== title)) { results.push({ face: face.name, reason: "title" }); continue; }
    const requested = `Requested by ${hostname}`;
    if (!lines.includes(requested)) { results.push({ face: face.name, reason: "requester", expected: requested }); continue; }
    const start = lines.indexOf(face.intro);
    const end = lines.indexOf(face.until, start + 1);
    if (start < 0 || end < 0) { results.push({ face: face.name, reason: "face_region" }); continue; }
    const region = lines.slice(start + 1, end);
    const notes = (face.notes ?? []).map((pattern) => new RegExp(pattern));
    const permissions = region.filter((line) => !notes.some((note) => note.test(line)));
    const noteLines = region.filter((line) => notes.some((note) => note.test(line)));
    const expected = [...face.permissions].sort();
    const actual = [...permissions].sort();
    const missing = expected.filter((line, i, all) => actual.filter((x) => x === line).length < all.filter((x) => x === line).length).filter((line, i, all) => all.indexOf(line) === i);
    const extra = actual.filter((line, i, all) => expected.filter((x) => x === line).length < all.filter((x) => x === line).length).filter((line, i, all) => all.indexOf(line) === i);
    if (missing.length || extra.length) { results.push({ face: face.name, reason: "permissions", missing, extra }); continue; }
    if (noteLines.length > 1) { results.push({ face: face.name, reason: "note_count", notes: noteLines.length }); continue; }
    const originAt = lines.indexOf("Verified browser origin");
    if (originAt < 0 || lines[originAt + 1] !== hostOrigin) { results.push({ face: face.name, reason: "verified_origin" }); continue; }
    return { ok: true, face: face.name };
  }
  // The closest miss is the one that got furthest through the checks.
  const order = ["forbidden_text", "title", "requester", "face_region", "permissions", "note_count", "verified_origin"];
  const closest = results.sort((a, b) => order.indexOf(b.reason) - order.indexOf(a.reason))[0] ?? { reason: "no_expected_faces" };
  return { ok: false, ...closest };
}
