#!/bin/sh
#
# Behavioral smoke test for `aguara check --ecosystem npm`. Builds four
# fixture trees under /tmp inside the container and verifies that the
# compromised-package detection chains correctly. Pure structural
# assertions on the CLI output; no fragile exact-count checks against
# the embedded IOC list.
#
# Exits non-zero on the first failed assertion so `make smoke-docker`
# surfaces the regression immediately.
set -eu

OUT="${BENCH_OUT:-/out}"
# Pre-create Go's cache and temp dirs. The bench image sets
# GOCACHE=/tmp/go-build and GOTMPDIR=/tmp/go-tmp, and the container
# runs with --read-only + a fresh /tmp tmpfs, so the `go build` below
# fails without these directories. Matches the prelude in run.sh and
# race.sh so all three entrypoints share the same shape.
mkdir -p /tmp/go-build /tmp/go-tmp "$OUT"
FIX_ROOT="/tmp/smoke-npm"
rm -rf "$FIX_ROOT"
mkdir -p "$FIX_ROOT"

# Build the binary with real ldflags so the JSON output's tool_version
# field matches the provenance record from bench-docker.
PKG="github.com/garagon/aguara/cmd/aguara/commands"
LDFLAGS="-s -w -X ${PKG}.Version=${AGUARA_VERSION:-dev} -X ${PKG}.Commit=${AGUARA_COMMIT:-none}"
go build -trimpath -ldflags "$LDFLAGS" -o /tmp/aguara ./cmd/aguara

fail() {
  echo "SMOKE FAIL: $1" >&2
  exit 1
}

ok() {
  printf 'SMOKE OK  : %s\n' "$1"
}

# --- Case 1: compromised event-stream 3.3.6 ---
case1="$FIX_ROOT/compromised"
mkdir -p "$case1/node_modules/event-stream"
printf '{"name":"event-stream","version":"3.3.6"}\n' \
  > "$case1/node_modules/event-stream/package.json"

case1_json="$OUT/smoke-npm-compromised.json"
/tmp/aguara --no-update-check check --ecosystem npm \
  --path "$case1/node_modules" --format json > "$case1_json"

if ! grep -Eq '"severity":[[:space:]]*"CRITICAL"' "$case1_json"; then
  cat "$case1_json"
  fail "compromised case missing CRITICAL severity"
fi
if ! grep -q 'GHSA-mh6f-8j2x-4483' "$case1_json"; then
  cat "$case1_json"
  fail "compromised case missing event-stream advisory GHSA-mh6f-8j2x-4483"
fi
ok "compromised event-stream 3.3.6 flagged CRITICAL with advisory"

# --- Case 2: clean express ---
case2="$FIX_ROOT/clean"
mkdir -p "$case2/node_modules/express"
printf '{"name":"express","version":"4.18.2"}\n' \
  > "$case2/node_modules/express/package.json"

case2_json="$OUT/smoke-npm-clean.json"
/tmp/aguara --no-update-check check --ecosystem npm \
  --path "$case2/node_modules" --format json > "$case2_json"

# Clean tree must emit an empty findings array, NOT null. The JSON
# encoder pretty-prints with `enc.SetIndent`, so the matcher allows
# optional whitespace between key and value.
if grep -Eq '"findings":[[:space:]]*null' "$case2_json"; then
  cat "$case2_json"
  fail "clean case emitted findings: null (regression of JSON stability fix)"
fi
if ! grep -Eq '"findings":[[:space:]]*\[\]' "$case2_json"; then
  cat "$case2_json"
  fail "clean case missing findings: []"
fi
ok "clean express tree produced findings: []"

# --- Case 3: nested fixture trees inside a real package ---
case3="$FIX_ROOT/fixture"
mkdir -p "$case3/node_modules/build-tool/examples/app/node_modules/event-stream"
printf '{"name":"build-tool","version":"1.0.0"}\n' \
  > "$case3/node_modules/build-tool/package.json"
printf '{"name":"event-stream","version":"3.3.6"}\n' \
  > "$case3/node_modules/build-tool/examples/app/node_modules/event-stream/package.json"

case3_json="$OUT/smoke-npm-fixture.json"
/tmp/aguara --no-update-check check --ecosystem npm \
  --path "$case3/node_modules" --format json > "$case3_json"

if grep -Eq '"severity":[[:space:]]*"CRITICAL"' "$case3_json"; then
  cat "$case3_json"
  fail "fixture nested manifest was treated as an installed dep"
fi
ok "fixture event-stream under examples/.../node_modules was correctly ignored"

# --- Case 4: bare directory without a node_modules subtree ---
case4="$FIX_ROOT/empty"
mkdir -p "$case4"

if /tmp/aguara --no-update-check check --ecosystem npm \
     --path "$case4" --format json > "$OUT/smoke-npm-bare.txt" 2>&1; then
  cat "$OUT/smoke-npm-bare.txt"
  fail "bare directory must error, not return a falsely-clean result"
fi
ok "bare directory without node_modules errored explicitly"

# --- Case 5: node-ipc 12.0.1 from the May 2026 Socket advisory ---
case5="$FIX_ROOT/node-ipc-2026"
mkdir -p "$case5/node_modules/node-ipc"
printf '{"name":"node-ipc","version":"12.0.1"}\n' \
  > "$case5/node_modules/node-ipc/package.json"

case5_json="$OUT/smoke-npm-node-ipc.json"
/tmp/aguara --no-update-check check --ecosystem npm \
  --path "$case5/node_modules" --format json > "$case5_json"

if ! grep -Eq '"severity":[[:space:]]*"CRITICAL"' "$case5_json"; then
  cat "$case5_json"
  fail "node-ipc 12.0.1 must surface as CRITICAL"
fi
if ! grep -q '"node-ipc 12.0.1' "$case5_json"; then
  cat "$case5_json"
  fail "node-ipc 12.0.1 finding missing exact name/version anchor"
fi
if ! grep -q 'SOCKET-2026-05-14-node-ipc' "$case5_json"; then
  cat "$case5_json"
  fail "node-ipc 12.0.1 finding missing SOCKET-2026-05-14-node-ipc advisory"
fi
ok "node-ipc 12.0.1 flagged CRITICAL with SOCKET-2026-05-14 advisory"

echo
echo "all npm incident smokes passed"
