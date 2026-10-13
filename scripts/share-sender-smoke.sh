#!/usr/bin/env bash
# Release check (TC-994): a brand-new throwaway OpenKey account signs in to
# production Share (share.tinycloud.xyz), creates a share and opens it.
# OpenKey changes that break embedding apps (as TC-688 did for Share) fail here.
#
# Runs Share's own smoke (test/e2e-prod/sender-signin-smoke.mjs) from a fresh
# clone. Needs git, Node 20+ and npm; Puppeteer downloads its Chrome on install.
#   SHARE_REF             Share branch or tag to take the smoke from (default main)
#   SHARE_SMOKE_ARTIFACT  where to write the scrubbed JSON report (optional)
# Prints one JSON line and exits non-zero on failure.
set -euo pipefail

share_ref="${SHARE_REF:-main}"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/openkey-share-smoke.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

git clone --quiet --depth 1 --branch "$share_ref" https://github.com/TinyCloudLabs/share.git "$workdir/share"
cd "$workdir/share"
npm ci --no-audit --no-fund --loglevel=error >/dev/null
npm run --silent test:e2e:sender-signin
