import { readFileSync } from 'node:fs';

export type BuildInfo = { version: string; commit: string };

const UNKNOWN = 'unknown';

let cachedVersion: string | undefined;

// The `version` field of apps/api/package.json, which the runtime image ships
// next to src/. Cached after the first read; any read or parse problem yields "unknown".
function readPackageVersion(): string {
  if (cachedVersion !== undefined) return cachedVersion;
  let version = UNKNOWN;
  try {
    const pkg: unknown = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    const value = (pkg as { version?: unknown } | null)?.version;
    if (typeof value === 'string' && value.trim() !== '') version = value.trim();
  } catch {
    // Leave "unknown": reporting build info never affects readiness.
  }
  cachedVersion = version;
  return version;
}

// `version` comes from package.json; `commit` comes from the GIT_SHA build
// argument (exported as the GIT_SHA environment variable in the image).
export function readBuildInfo(env: Record<string, string | undefined> = process.env): BuildInfo {
  const commit = env.GIT_SHA?.trim();
  return { version: readPackageVersion(), commit: commit ? commit : UNKNOWN };
}
