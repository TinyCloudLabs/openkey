// Shared logic for creating GitHub Releases from package tags.
//
// Tags look like `@openkey/sdk@0.12.1-beta.1` (created by `changeset publish`).
// Release title = tag name, body = the package CHANGELOG section for that
// version, prerelease = any version with a `-` suffix, "latest" = stable
// @openkey/sdk only. Everything here is idempotent: an existing Release is
// never touched.
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const TAG_RE = /^(@openkey\/[a-z0-9][a-z0-9-]*)@(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$/;
export const LATEST_PACKAGE = '@openkey/sdk';

/** `@openkey/sdk@0.12.1-beta.1` -> { name, version, ... }; null for any other tag. */
export function parseTag(tag) {
  const m = TAG_RE.exec(tag);
  if (!m) return null;
  const [, name, major, minor, patch, pre] = m;
  return {
    tag,
    name,
    version: `${major}.${minor}.${patch}${pre ?? ''}`,
    core: [Number(major), Number(minor), Number(patch)],
    prerelease: pre !== undefined,
  };
}

export function isPrerelease(version) {
  return /^\d+\.\d+\.\d+-/.test(version);
}

/** Only a stable @openkey/sdk release may be marked "latest". */
export function isLatestCandidate(tag) {
  const parsed = parseTag(tag);
  return parsed !== null && parsed.name === LATEST_PACKAGE && !parsed.prerelease;
}

function compareCore(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/** Highest stable @openkey/sdk tag in the list, or null. */
export function pickLatestTag(tags) {
  let best = null;
  for (const tag of tags) {
    if (!isLatestCandidate(tag)) continue;
    const p = parseTag(tag);
    if (best === null || compareCore(p.core, best.core) > 0) best = p;
  }
  return best?.tag ?? null;
}

/** Body of the `## <version>` section of a changesets CHANGELOG, or null. */
export function extractChangelogSection(markdown, version) {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trimEnd() === `## ${version}`);
  if (start === -1) return null;
  let end = lines.findIndex((line, i) => i > start && /^## /.test(line));
  if (end === -1) end = lines.length;
  const body = lines.slice(start + 1, end).join('\n').trim();
  return body === '' ? null : body;
}

export function buildNotes({ name, version, section }) {
  const npm = `https://www.npmjs.com/package/${name}/v/${version}`;
  const body = section ?? `No changelog entry was recorded for ${name} ${version}.`;
  return `${body}\n\n---\n\nnpm: [${name}@${version}](${npm})\n`;
}

/** package name -> directory, from packages/*\/package.json. */
export function packageDirs(root = '.') {
  const dirs = new Map();
  const base = join(root, 'packages');
  for (const entry of readdirSync(base, { withFileTypes: true })) {
    const file = join(base, entry.name, 'package.json');
    if (!entry.isDirectory() || !existsSync(file)) continue;
    dirs.set(JSON.parse(readFileSync(file, 'utf8')).name, join(base, entry.name));
  }
  return dirs;
}

export function notesForTag(parsed, dirs) {
  const dir = dirs.get(parsed.name);
  const changelog = dir ? join(dir, 'CHANGELOG.md') : null;
  const section =
    changelog && existsSync(changelog)
      ? extractChangelogSection(readFileSync(changelog, 'utf8'), parsed.version)
      : null;
  return buildNotes({ name: parsed.name, version: parsed.version, section });
}

/** Tags with their creation time, oldest first. */
export function listTagsWithDates() {
  const out = execFileSync(
    'git',
    ['for-each-ref', '--sort=creatordate', '--format=%(refname:short)\t%(creatordate:unix)', 'refs/tags'],
    { encoding: 'utf8' },
  );
  return out
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [tag, unix] = line.split('\t');
      return { tag, time: Number(unix) };
    });
}

function gh(args, input) {
  return spawnSync('gh', args, { encoding: 'utf8', input });
}

export function releaseExists(tag) {
  const res = gh(['release', 'view', tag]);
  if (res.status === 0) return true;
  if (/release not found/i.test(res.stderr)) return false;
  throw new Error(`gh release view ${tag} failed: ${res.stderr || res.error}`);
}

/**
 * Create a Release for every parseable tag in `tags` that has none yet.
 * Returns [{ tag, action: 'create' | 'skip-exists' | 'skip-unparsed', ... }].
 */
export function createReleases(tags, { dryRun = false, latestTag = pickLatestTag(tags), root = '.' } = {}) {
  const dirs = packageDirs(root);
  const results = [];
  for (const tag of tags) {
    const parsed = parseTag(tag);
    if (!parsed) {
      results.push({ tag, action: 'skip-unparsed' });
      continue;
    }
    if (releaseExists(tag)) {
      results.push({ tag, action: 'skip-exists' });
      continue;
    }
    const prerelease = isPrerelease(parsed.version);
    const latest = tag === latestTag;
    const result = { tag, action: 'create', prerelease, latest };
    if (!dryRun) {
      const args = ['release', 'create', tag, '--title', tag, '--notes-file', '-', '--verify-tag'];
      if (prerelease) args.push('--prerelease');
      args.push(latest ? '--latest' : '--latest=false');
      const res = gh(args, notesForTag(parsed, dirs));
      if (res.status !== 0) throw new Error(`gh release create ${tag} failed: ${res.stderr || res.error}`);
    }
    results.push(result);
  }
  return results;
}

export function formatResults(results, dryRun) {
  const created = results.filter((r) => r.action === 'create');
  const lines = results.map((r) => {
    if (r.action !== 'create') return `${r.action.padEnd(14)} ${r.tag}`;
    const flags = [r.prerelease ? 'prerelease' : 'stable', r.latest ? 'latest' : null].filter(Boolean);
    return `${(dryRun ? 'would-create' : 'created').padEnd(14)} ${r.tag} (${flags.join(', ')})`;
  });
  lines.push('', `${dryRun ? 'would create' : 'created'} ${created.length} of ${results.length} tags`);
  return lines.join('\n');
}
