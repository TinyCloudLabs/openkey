#!/usr/bin/env node
// Fails when a build artifact holds something a public host must not serve:
// sourcemaps, dotfiles, a file type outside the allow-list, a secret-shaped
// string or a machine-local name. With --gitleaks it then runs a pinned
// `gitleaks dir` over each directory. Reports name the file and the pattern,
// never the matched value. Generalised from rocinante-sitrep scripts/audit-public.mjs.
// Each --require-text=<string> must appear in at least one scanned file.
//
//   node scripts/security/audit-artifact.mjs [--gitleaks] [--allow-ext=.js,.css] [--allow-name=_headers] [--require-text=<string>] <dir>...
//
// `bun run audit:web` runs it on the Cloudflare Pages web build; see docs/security/required-checks.md.
import { execFileSync } from 'node:child_process';
import { lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const DEFAULT_EXT = ['.html', '.js', '.mjs', '.css', '.json', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.ico', '.woff', '.woff2', '.ttf', '.txt', '.webmanifest', '.wasm'];
// Cloudflare Pages control files have no extension.
const DEFAULT_NAMES = ['_headers', '_redirects'];

const SECRETS = [
  { label: 'Stripe live key (sk_live_/rk_live_)', re: /\b[sr]k_live_[0-9A-Za-z]{8,}/g },
  { label: 'PEM block (-----BEGIN)', re: /-----BEGIN[A-Z0-9 ]*-----/g },
  { label: '32-byte hex (0x + 64 hex, private-key sized)', re: /\b0x[0-9a-fA-F]{64}(?![0-9a-fA-F])/g },
  { label: 'Slack token (xoxb-/xoxp-)', re: /\bxox[bp]-[0-9A-Za-z-]{10,}/g },
  { label: 'JWT (eyJ….eyJ…)', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}/g },
  { label: 'AWS access key id (AKIA)', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: 'GitHub token (ghp_/gho_/ghu_/ghs_/ghr_)', re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g },
  { label: 'GitHub fine-grained token (github_pat_)', re: /\bgithub_pat_[A-Za-z0-9_]{22,}/g },
  { label: 'npm token (npm_)', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
];
const MACHINE_LOCAL = [
  { label: 'tailnet host (.ts.net)', re: /(?<![A-Za-z0-9])[A-Za-z0-9-]+\.ts\.net(?![A-Za-z0-9])/g },
  { label: 'home directory path', re: /(?:\/home\/[a-z_][a-z0-9_-]*|\/Users\/[A-Za-z][A-Za-z0-9._-]*)\//g },
  { label: 'loopback URL with a port', re: /\b(?:localhost|127\.0\.0\.1):\d{2,5}\b/g },
];

function parseArgs(argv) {
  const options = { gitleaks: false, ext: DEFAULT_EXT, names: DEFAULT_NAMES, requireText: [], dirs: [] };
  for (const arg of argv) {
    if (arg === '--gitleaks') options.gitleaks = true;
    else if (arg.startsWith('--allow-ext=')) options.ext = arg.slice(12).split(',').filter(Boolean);
    else if (arg.startsWith('--allow-name=')) options.names = arg.slice(13).split(',').filter(Boolean);
    else if (arg.startsWith('--require-text=')) options.requireText.push(arg.slice('--require-text='.length));
    else if (arg.startsWith('--')) throw new Error(`unknown option ${arg}`);
    else options.dirs.push(resolve(arg));
  }
  if (options.dirs.length === 0) throw new Error('no artifact directory given');
  return options;
}

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isSymbolicLink()) return [path];
    return entry.isDirectory() ? walk(path) : [path];
  });
}

function missingTextProblems(missingText) {
  return Array.from(missingText, (text) => `required text not found in any file: ${text}`);
}

export function auditDirectory(dir, { requireText = [], ...options } = {}) {
  const missingText = new Set(requireText);
  const result = scanDirectory(dir, options, missingText);
  result.problems.push(...missingTextProblems(missingText));
  return result;
}

function scanDirectory(dir, { ext = DEFAULT_EXT, names = DEFAULT_NAMES }, missingText) {
  const allowedExt = new Set(ext);
  const allowedNames = new Set(names);
  const problems = [];
  const files = walk(dir).sort();
  for (const file of files) {
    const name = relative(dir, file).split('\\').join('/');
    const base = basename(name);
    if (!lstatSync(file).isFile()) {
      problems.push(`${name}: not a regular file`);
      continue;
    }
    if (extname(base) === '.map') problems.push(`${name}: sourcemap file`);
    if (base.startsWith('.')) problems.push(`${name}: dotfile`);
    else if (!allowedExt.has(extname(base)) && !allowedNames.has(base)) problems.push(`${name}: file type not on the allow-list`);
    const contents = readFileSync(file);
    if (missingText.size > 0) {
      for (const required of missingText) {
        if (contents.includes(required)) missingText.delete(required);
      }
    }
    // latin1 keeps every byte, so binary files are scanned too.
    const text = contents.toString('latin1');
    if (/[#@]\s*sourceMappingURL=/.test(text)) problems.push(`${name}: sourceMappingURL`);
    for (const { label, re } of [...SECRETS, ...MACHINE_LOCAL]) {
      const count = text.match(re)?.length ?? 0;
      if (count > 0) problems.push(`${name}: ${label} x${count}`);
    }
  }
  return { files: files.length, problems };
}

function runGitleaks(dirs) {
  const scratch = mkdtempSync(join(tmpdir(), 'audit-artifact-'));
  try {
    const bin = installToolSync(scratch);
    for (const dir of dirs) {
      // -i points at an empty directory: the repo's .gitleaksignore baselines commits, never artifacts.
      // --ignore-gitleaks-allow: a `gitleaks:allow` comment in shipped code must not hide a finding.
      execFileSync(bin, ['dir', '--config', join(REPO_ROOT, '.gitleaks.toml'), '-i', scratch, '--ignore-gitleaks-allow', '--redact', '--no-banner', '--exit-code', '1', dir], { stdio: 'inherit' });
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

// installTool is async (fetch); run it in a child so this stays a straight-line script.
function installToolSync(scratch) {
  const toolDir = join(scratch, 'bin');
  execFileSync(process.execPath, [fileURLToPath(new URL('./install-tool.mjs', import.meta.url)), 'gitleaks', toolDir], { stdio: ['ignore', 'ignore', 'inherit'] });
  return join(toolDir, 'gitleaks');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`audit-artifact: ${error.message}`);
    process.exit(2);
  }
  let failed = false;
  const missingText = new Set(options.requireText);
  for (const dir of options.dirs) {
    if (statSync(dir, { throwIfNoEntry: false })?.isDirectory() !== true) {
      console.error(`audit-artifact: ${dir} does not exist; build it first`);
      process.exit(1);
    }
    const { files, problems } = scanDirectory(dir, options, missingText);
    console.log(`audit-artifact: scanned ${files} files in ${relative(REPO_ROOT, dir) || dir}`);
    if (files === 0) problems.push('no files: an empty artifact proves nothing');
    for (const problem of problems) console.error(`  - ${problem}`);
    failed ||= problems.length > 0;
  }
  for (const problem of missingTextProblems(missingText)) console.error(`  - ${problem}`);
  failed ||= missingText.size > 0;
  if (failed) {
    console.error('audit-artifact: FAILED');
    process.exit(1);
  }
  if (options.gitleaks) {
    try {
      runGitleaks(options.dirs);
    } catch (error) {
      console.error(`audit-artifact: gitleaks failed (${error.status ?? error.message})`);
      process.exit(1);
    }
  }
  console.log('audit-artifact: passed');
}
