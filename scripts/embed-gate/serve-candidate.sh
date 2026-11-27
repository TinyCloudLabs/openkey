#!/usr/bin/env bash
# Serves the built OpenKey web (apps/web/.svelte-kit/cloudflare) as https://openkey.so on 127.0.0.1 for the
# embed gate: `wrangler pages dev` runs the Pages worker (hooks.server.ts, so the frame policy applies), with
# a throwaway certificate made here. Chromium reaches it through --host-resolver-rules and trusts it only by
# its SPKI pin. Prints `port=`, `spki=` and `pid=` lines (for $GITHUB_OUTPUT).
#
# It reports ready once /widget/embed/connect answers 200, and prints the frame headers of the connect page and
# /auth/login for the log. It judges nothing: the browser run decides whether the frames behave.
set -euo pipefail

port="${EMBED_GATE_CANDIDATE_PORT:-18443}"
dir="${EMBED_GATE_TLS_DIR:-${RUNNER_TEMP:-/tmp}/embed-gate-tls}"
build="${EMBED_GATE_BUILD_DIR:-apps/web/.svelte-kit/cloudflare}"
log="${EMBED_GATE_SERVER_LOG:-${RUNNER_TEMP:-/tmp}/embed-gate-wrangler.log}"
mkdir -p "$dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=openkey.so" \
  -addext "subjectAltName=DNS:openkey.so" -keyout "$dir/key.pem" -out "$dir/cert.pem" 2>/dev/null
spki="$(openssl x509 -in "$dir/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"

# The compatibility date is the Pages project's production setting (it has no wrangler.toml in this repo).
nohup node_modules/.bin/wrangler pages dev "$build" --ip 127.0.0.1 --port "$port" --local-protocol https \
  --https-key-path "$dir/key.pem" --https-cert-path "$dir/cert.pem" \
  --compatibility-date "${EMBED_GATE_COMPATIBILITY_DATE:-2025-01-01}" > "$log" 2>&1 &
pid=$!

probe() { curl -s -o /dev/null -D - --max-time 10 --cacert "$dir/cert.pem" --resolve "openkey.so:$port:127.0.0.1" "https://openkey.so:$port$1"; }
for _ in $(seq 1 60); do
  if probe /widget/embed/connect | grep -q '^HTTP/[0-9.]* 200'; then break; fi
  if ! kill -0 "$pid" 2>/dev/null; then echo "wrangler exited; log:" >&2; tail -40 "$log" >&2; exit 1; fi
  sleep 2
done
connect="$(probe /widget/embed/connect)"
login="$(probe /auth/login)"
grep -q '^HTTP/[0-9.]* 200' <<< "$connect" || { echo "the candidate never served /widget/embed/connect" >&2; tail -40 "$log" >&2; exit 1; }
echo "candidate frame headers: connect [$(grep -i -E "^(content-security-policy|x-frame-options):" <<< "$connect" | tr -d '\r' | paste -sd ';' -)]; /auth/login [$(grep -i -E "^(content-security-policy|x-frame-options):" <<< "$login" | tr -d '\r' | paste -sd ';' -)]" >&2
echo "port=$port"
echo "spki=$spki"
echo "pid=$pid"
