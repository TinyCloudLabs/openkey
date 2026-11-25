#!/usr/bin/env bash
# Release order: preview -> QA probe -> production. Roll back with
# POST /accounts/$CLOUDFLARE_ACCOUNT_ID/pages/projects/openkey/deployments/<id>/rollback.
# If Pages git builds are re-enabled, append "&& bun run audit:web:prod" to
# the project's build_command as well; this script audits the uploaded artifact.
set -euo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

[[ $# == 2 || $# == 4 ]] || die 'Usage: openkey-web-direct-upload.sh <commit-sha> preview|production [--preview-verified <preview deployment id>]'
sha=$1
mode=$2
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die 'Expected a full lowercase commit SHA'
case "$mode" in
  preview) [[ $# == 2 ]] || die 'Preview takes no extra arguments' ;;
  production)
    [[ $# == 4 && $3 == --preview-verified && $4 =~ ^[0-9a-fA-F-]+$ ]] ||
      die 'Production requires --preview-verified <preview deployment id>'
    preview_id=$4
    ;;
  *) die 'Mode must be preview or production' ;;
esac
: "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
: "${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"
: "${HOME:?HOME is required}"
token=$CLOUDFLARE_API_TOKEN
account=$CLOUDFLARE_ACCOUNT_ID
unset CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID
safe_env=("PATH=$PATH" "HOME=$HOME")

cd "$(dirname "$0")/../.."
[[ "$(git rev-parse HEAD)" == "$sha" ]] || die 'HEAD does not match the requested commit'
[[ -z "$(git status --porcelain)" ]] || die 'Working tree is not clean'

base="https://api.cloudflare.com/client/v4/accounts/$account/pages/projects/openkey"
cf_get() {
  env -i "${safe_env[@]}" curl --fail --silent --show-error -H "Authorization: Bearer $token" "$1"
}

project=$(cf_get "$base")
jq -e '.success == true and (.result.deployment_configs.production.env_vars | type == "object") and
  .result.build_config.build_command == "bun install && bun run build --filter @openkey/web" and
  (.result.source.config.production_branch | type == "string" and length > 0)' <<<"$project" >/dev/null ||
  die 'Incomplete Cloudflare Pages project configuration'
env_vars=$(jq -c '.result.deployment_configs.production.env_vars' <<<"$project")
jq -e 'all(.[]; .type == "plain_text" and (.value | type == "string")) and
  (.VITE_API_URL.value | type == "string" and length > 0) and
  (keys | all(.[]; test("^VITE_[A-Z0-9_]+$")))' <<<"$env_vars" >/dev/null ||
  die 'Production variables include unreadable/invalid entries or VITE_API_URL is missing'

vite_env=()
while IFS= read -r -d '' name && IFS= read -r -d '' value; do
  vite_env+=("$name=$value")
  printf 'Build environment: %s\n' "$name"
done < <(jq -j 'to_entries[] | .key, "\u0000", .value.value, "\u0000"' <<<"$env_vars")

api_host=$(jq -er '.VITE_API_URL.value | capture("^https?://(?<host>[^/:?#]+)").host' <<<"$env_vars") ||
  die 'VITE_API_URL must be an absolute HTTP(S) URL'
if [[ "$mode" == production ]]; then
  verified=$(cf_get "$base/deployments/$preview_id")
  jq -e --arg sha "$sha" '.success == true and .result.environment == "preview" and
    .result.deployment_trigger.metadata.commit_hash == $sha and .result.latest_stage.status == "success"' \
    <<<"$verified" >/dev/null || die 'Preview deployment is not successful for this commit'
  previous=$(jq -er '.result.canonical_deployment.id | select(type == "string" and length > 0)' <<<"$project") ||
    die 'No previous canonical deployment to roll back to'
  printf 'Rollback target (previous canonical deployment): %s\n' "$previous"
fi

env -i "${safe_env[@]}" "${vite_env[@]}" bun install --frozen-lockfile
env -i "${safe_env[@]}" "${vite_env[@]}" bun run build --filter @openkey/web
dist=apps/web/.svelte-kit/cloudflare
[[ -d "$dist" ]] || die "Build output missing: $dist"
env -i "${safe_env[@]}" grep -R -q -F -- "$api_host" "$dist" || die 'Build output does not contain the VITE_API_URL host'
env -i "${safe_env[@]}" bun run audit:web:prod

branch="preview-${sha:0:8}"
if [[ "$mode" == production ]]; then
  branch=$(jq -r '.result.source.config.production_branch' <<<"$project")
fi
upload=$(env -i "${safe_env[@]}" "CLOUDFLARE_API_TOKEN=$token" "CLOUDFLARE_ACCOUNT_ID=$account" \
  wrangler pages deploy "$dist" --project-name openkey --branch "$branch" --commit-hash "$sha")
if [[ "$mode" == preview ]]; then
  url=$(env -i "${safe_env[@]}" grep -Eo 'https://[a-zA-Z0-9-]+\.openkey\.pages\.dev' <<<"$upload" | tail -n 1)
  [[ -n "$url" ]] || die 'Wrangler did not return a unique preview deployment URL'
  printf 'Preview deployment: %s\n' "$url"
  for path in /auth/register /auth/login; do
    status=$(env -i "${safe_env[@]}" curl --fail --silent --show-error --location --output /dev/null --write-out '%{http_code}' "$url$path")
    [[ "$status" == 200 ]] || die "Preview $path returned HTTP $status"
  done
else
  deployed=$(cf_get "$base")
  jq -e --arg sha "$sha" '.success == true and
    .result.canonical_deployment.deployment_trigger.metadata.commit_hash == $sha and
    .result.canonical_deployment.latest_stage.status == "success"' \
    <<<"$deployed" >/dev/null || die 'Canonical deployment does not match the successful requested commit'
  jq -er '.result.canonical_deployment.id | select(type == "string" and length > 0)' <<<"$deployed" ||
    die 'Canonical deployment ID is missing'
fi
