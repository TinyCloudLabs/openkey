#!/usr/bin/env node
// Installs a pinned security scanner (gitleaks or trivy) into <dir> after checking
// the release archive's sha256 against the value pinned here, then prints <dir>.
// Any download, checksum or extract failure exits non-zero: the checks that use
// these tools fail closed. To upgrade, change the version and every sha256 from
// the release's published checksums file in one reviewed commit.
//
//   node scripts/security/install-tool.mjs gitleaks "$RUNNER_TEMP/gitleaks" >> "$GITHUB_PATH"
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const TOOLS = {
  gitleaks: {
    version: '8.30.1',
    url: (v, asset) => `https://github.com/gitleaks/gitleaks/releases/download/v${v}/${asset}`,
    assets: {
      'linux-x64': ['gitleaks_8.30.1_linux_x64.tar.gz', '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'],
      'linux-arm64': ['gitleaks_8.30.1_linux_arm64.tar.gz', 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080'],
      'darwin-x64': ['gitleaks_8.30.1_darwin_x64.tar.gz', 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709'],
      'darwin-arm64': ['gitleaks_8.30.1_darwin_arm64.tar.gz', 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5'],
    },
  },
  trivy: {
    version: '0.76.2',
    url: (v, asset) => `https://github.com/aquasecurity/trivy/releases/download/v${v}/${asset}`,
    assets: {
      'linux-x64': ['trivy_0.76.2_Linux-64bit.tar.gz', 'bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf'],
      'linux-arm64': ['trivy_0.76.2_Linux-ARM64.tar.gz', 'ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3'],
      'darwin-arm64': ['trivy_0.76.2_macOS-ARM64.tar.gz', 'ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8'],
    },
  },
};

export async function installTool(name, dir) {
  const tool = TOOLS[name];
  if (!tool) throw new Error(`unknown tool ${name}; expected one of ${Object.keys(TOOLS).join(', ')}`);
  const platform = `${process.platform}-${process.arch}`;
  const pinned = tool.assets[platform];
  if (!pinned) throw new Error(`${name} ${tool.version} has no pinned build for ${platform}`);
  const [asset, sha256] = pinned;
  const response = await fetch(tool.url(tool.version, asset));
  if (!response.ok) throw new Error(`${name}: download of ${asset} failed with HTTP ${response.status}`);
  const archive = Buffer.from(await response.arrayBuffer());
  const actual = createHash('sha256').update(archive).digest('hex');
  if (actual !== sha256) throw new Error(`${name}: ${asset} sha256 ${actual} does not match the pinned ${sha256}`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const staging = mkdtempSync(join(tmpdir(), `${name}-archive-`));
  try {
    const archivePath = join(staging, asset);
    writeFileSync(archivePath, archive, { mode: 0o600 });
    execFileSync('tar', ['-xzf', archivePath, '-C', dir, name], { stdio: ['ignore', 'ignore', 'inherit'] });
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
  const bin = join(dir, name);
  if (!existsSync(bin)) throw new Error(`${name}: ${asset} did not contain ${name}`);
  chmodSync(bin, 0o755);
  return bin;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [name, dir] = process.argv.slice(2);
  if (!name || !dir) {
    console.error('usage: install-tool.mjs <gitleaks|trivy> <dir>');
    process.exit(2);
  }
  try {
    await installTool(name, resolve(dir));
    console.log(resolve(dir));
  } catch (error) {
    console.error(`install-tool: ${error.message}`);
    process.exit(1);
  }
}
