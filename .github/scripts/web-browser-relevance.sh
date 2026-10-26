#!/usr/bin/env bash
# Decides whether the web browser specs need to run for a change (TC-2120).
#
# Prints two lines on stdout, for $GITHUB_OUTPUT:
#   relevant=true|false
#   reason=<one line>
#
# It fails OPEN: only a clean `git diff` that lists files, none of them on a relevant path, skips
# the specs. A non-pull-request event, a git failure and an empty file list all run them.
#
# Environment: EVENT (github.event_name), BASE (base commit of the pull request), HEAD (merge commit).
# `--stdin` reads the changed file names from stdin, not from git; the tests use it.

set -u

# Paths whose change can move a browser spec: the web app, what it builds from, the SDK the
# handshake spec loads from its dist/, the lockfile and manifests, and this workflow's own files.
is_relevant_path() {
  case "$1" in
    apps/web/*|packages/capability-review/*|packages/sdk/*|packages/core/*|packages/types/*) return 0 ;;
    bun.lock|package.json|turbo.json) return 0 ;;
    .github/workflows/web-browser-tests.yml|.github/web-browser-known-reds.json) return 0 ;;
    .github/scripts/web-browser-*) return 0 ;;
  esac
  return 1
}

decide() {
  local files="$1" file first=""
  if [[ -z "$files" ]]; then
    echo "relevant=true"
    echo "reason=the list of changed files is empty, so the specs run"
    return
  fi
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    if is_relevant_path "$file"; then
      first="$file"
      break
    fi
  done <<< "$files"
  if [[ -n "$first" ]]; then
    echo "relevant=true"
    echo "reason=a relevant path changed: $first"
  else
    echo "relevant=false"
    echo "reason=no web app, capability review, SDK or workflow path changed in this pull request"
  fi
}

if [[ "${1:-}" == "--stdin" ]]; then
  decide "$(cat)"
  exit 0
fi

if [[ "${EVENT:-}" != "pull_request" ]]; then
  echo "relevant=true"
  echo "reason=event ${EVENT:-unknown} always runs the specs"
  exit 0
fi

if ! files="$(git diff --no-renames --name-only "${BASE:-}" "${HEAD:-}" 2>/dev/null)"; then
  echo "relevant=true"
  echo "reason=git diff failed, so the specs run"
  exit 0
fi
decide "$files"
