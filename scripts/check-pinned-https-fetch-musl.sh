#!/usr/bin/env bash
# Run from any directory: bash scripts/check-pinned-https-fetch-musl.sh [image tag or sha256:digest]
# Runs the pinned HTTPS gate on the Bun inside the API image base without a container daemon: the image layers come
# from the registry API and run in a chroot inside user/net/mount namespaces. The default is the oven/bun digest
# in the Dockerfile base line; an argument overrides it with a tag (1.2, 1.2.23, 1.2-alpine) or a digest.
# A digest may name the image index or the linux/amd64 manifest. Prints both digests and `bun --revision`.
# Requires Linux user namespaces, curl, jq, tar, iproute2 and OpenSSL; downloads about 45 MB.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
ref=${1:-$(grep -m1 -oE '^FROM oven/bun:[^ @]+@sha256:[0-9a-f]{64}' "$repo/Dockerfile" | sed 's/.*@//')}
[[ -n $ref ]] || { echo "no oven/bun digest in $repo/Dockerfile and no argument" >&2; exit 1; }
case $ref in sha256:*) ;; *-alpine) ;; *) ref=$ref-alpine ;; esac
registry=https://registry-1.docker.io/v2/oven/bun
work=$(mktemp -d)
trap 'chmod -R u+w -- "$work" 2>/dev/null; rm -rf -- "$work"' EXIT
curl_registry() { curl --proto =https --proto-redir =https -fsSL --retry 3 -H "Authorization: Bearer $token" "$@"; }
token=$(curl --proto =https --proto-redir =https -fsSL 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:oven/bun:pull' | jq -er .token)

manifest_accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
curl_registry -H "Accept: $manifest_accept" "$registry/manifests/$ref" -o "$work/first.json"
first_digest=sha256:$(sha256sum < "$work/first.json" | cut -d' ' -f1)
[[ $ref != sha256:* || $ref == "$first_digest" ]] || { echo "digest mismatch: $ref != $first_digest" >&2; exit 1; }
if jq -e '.manifests' "$work/first.json" >/dev/null; then
  echo "image index digest: $first_digest"
  manifest_digest=$(jq -er '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest' "$work/first.json")
  curl_registry -H "Accept: $manifest_accept" "$registry/manifests/$manifest_digest" -o "$work/manifest.json"
  [[ sha256:$(sha256sum < "$work/manifest.json" | cut -d' ' -f1) == "$manifest_digest" ]] || { echo "manifest digest mismatch" >&2; exit 1; }
else
  manifest_digest=$first_digest
  mv "$work/first.json" "$work/manifest.json"
fi
echo "linux/amd64 manifest digest: $manifest_digest"

mkdir "$work/rootfs"
for digest in $(jq -er '.layers[].digest' "$work/manifest.json"); do
  curl_registry "$registry/blobs/$digest" -o "$work/layer"
  [[ sha256:$(sha256sum < "$work/layer" | cut -d' ' -f1) == "$digest" ]] || { echo "layer digest mismatch: $digest" >&2; exit 1; }
  # List to a file first: grep -q on a pipe exits early, tar then dies of SIGPIPE and pipefail hides the match.
  tar -tzf "$work/layer" > "$work/layer.list"
  if grep -Eq '(^|/)\.wh\.' "$work/layer.list"; then echo "unsupported whiteout in $digest" >&2; exit 1; fi
  tar -xzf "$work/layer" -C "$work/rootfs" --no-same-owner --exclude='dev/*'
done

modules=$(readlink -f "$repo/node_modules")
fixture=$work/fixture
mkdir "$fixture"
# The second certificate names manifest.test too but is never added to NODE_EXTRA_CA_CERTS.
for prefix in "" untrusted-; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=manifest.test \
    -addext subjectAltName=DNS:manifest.test -keyout "$fixture/${prefix}key.pem" -out "$fixture/${prefix}cert.pem" 2>/dev/null
done
unshare --user --map-root-user --net --mount bash -euc '
  rootfs=$1; repo=$2; modules=$3; fixture=$4; ip=$5
  "$ip" link set lo up
  "$ip" addr add 8.8.4.4/32 dev lo
  mkdir -p "$rootfs/app" "$rootfs/fixture" "$rootfs$modules"
  mount --rbind "$repo" "$rootfs/app"
  mount --rbind "$fixture" "$rootfs/fixture"
  mount --rbind "$modules" "$rootfs$modules"
  mount --rbind /proc "$rootfs/proc"
  mount --rbind /dev "$rootfs/dev"
  exec chroot "$rootfs" /bin/sh -euc "
    echo \"bun --revision: \$(/usr/local/bin/bun --revision) (\$(. /etc/os-release; echo \$PRETTY_NAME))\"
    cd /app
    NODE_EXTRA_CA_CERTS=/fixture/cert.pem /usr/local/bin/bun scripts/check-pinned-https-fetch.ts /fixture
    # Bun reads this variable at startup, so the second pass starts with verification switched off in the environment.
    echo NODE_TLS_REJECT_UNAUTHORIZED=0 at startup
    NODE_TLS_REJECT_UNAUTHORIZED=0 NODE_EXTRA_CA_CERTS=/fixture/cert.pem /usr/local/bin/bun scripts/check-pinned-https-fetch.ts /fixture
  "
' check-pinned-https-fetch-musl "$work/rootfs" "$repo" "$modules" "$fixture" "$(command -v ip)"
