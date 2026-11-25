#!/usr/bin/env bash
# Run from any directory: bash scripts/check-pinned-https-fetch.sh [path/to/bun]
# Requires Linux user/network namespaces, iproute2 and OpenSSL.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
bun=$(command -v -- "${1:-bun}")
fixture=$(mktemp -d)
trap 'rm -f -- "$fixture/key.pem" "$fixture/cert.pem"; rmdir -- "$fixture"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=manifest.test \
  -addext subjectAltName=DNS:manifest.test -keyout "$fixture/key.pem" -out "$fixture/cert.pem" 2>/dev/null
unshare --user --map-root-user --net bash -euc '
  ip link set lo up
  ip addr add 8.8.4.4/32 dev lo
  cd "$1"
  NODE_EXTRA_CA_CERTS="$3/cert.pem" "$2" scripts/check-pinned-https-fetch.ts "$3"
' check-pinned-https-fetch "$repo" "$bun" "$fixture"
