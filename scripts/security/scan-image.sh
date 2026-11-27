#!/usr/bin/env bash
# Fails if <image> has a fixable CRITICAL or HIGH vulnerability, or a secret, that
# isn't in the reviewed baseline .trivyignore.yaml. Installs the pinned trivy first.
# Used by .github/workflows/api-image-scan.yml (every PR and main push) and by the
# deploy job in deploy-api.yml on the exact image it is about to push.
#
#   scripts/security/scan-image.sh openkey-api:scan
set -euo pipefail
image="${1:?usage: scan-image.sh <image>}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
tools="$(mktemp -d)"
trap 'rm -rf "$tools"' EXIT
node "$root/scripts/security/install-tool.mjs" trivy "$tools" >/dev/null
"$tools/trivy" --version
"$tools/trivy" image \
  --severity CRITICAL,HIGH \
  --ignore-unfixed \
  --scanners vuln,secret \
  --ignorefile "$root/.trivyignore.yaml" \
  --exit-code 1 \
  --no-progress \
  "$image"
