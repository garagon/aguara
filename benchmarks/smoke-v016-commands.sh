#!/bin/sh
#
# Behavioral smoke test for the v0.16 native-threat-intel commands.
# Exercises each command documented in the README under the
# Supply-Chain Check section so docs and binary cannot drift:
#
#   aguara check              (auto-detect; offline)
#   aguara check --ci         (--fail-on critical, exit code)
#   aguara status             (no network; offline by definition)
#   aguara audit              (check + scan, single verdict)
#
# The --fresh / update paths are intentionally NOT exercised here.
# Both reach osv.dev over the network, and the smoke harness must
# stay hermetic (the bench image runs --read-only --network host
# only for go-build access). Coverage for those paths lives in
# internal/intel/update_test.go using httptest.NewServer.
#
# Exits non-zero on the first failed assertion so `make smoke-docker`
# surfaces the regression immediately.
set -eu

OUT="${BENCH_OUT:-/out}"
mkdir -p /tmp/go-build /tmp/go-tmp "$OUT"

FIX_ROOT="/tmp/smoke-v016"
rm -rf "$FIX_ROOT"
mkdir -p "$FIX_ROOT"

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

# --- Case 1: aguara check (no flags, auto-detect npm) ---------------
# The README's Quick Start leads with `aguara check`. The contract:
# (a) it must auto-detect node_modules when present without
# requiring --ecosystem, and (b) it must surface compromised
# packages with the manual SOCKET advisory ID.
case1="$FIX_ROOT/autodetect-npm"
mkdir -p "$case1/node_modules/event-stream"
printf '{"name":"event-stream","version":"3.3.6"}\n' \
  > "$case1/node_modules/event-stream/package.json"

case1_json="$OUT/smoke-v016-autodetect.json"
/tmp/aguara --no-update-check check --path "$case1" --format json > "$case1_json"

if ! grep -Eq '"severity":[[:space:]]*"CRITICAL"' "$case1_json"; then
  cat "$case1_json"
  fail "aguara check (auto-detect) missed event-stream 3.3.6 as CRITICAL"
fi
if ! grep -q 'GHSA-mh6f-8j2x-4483' "$case1_json"; then
  cat "$case1_json"
  fail "aguara check (auto-detect) missing event-stream advisory"
fi
ok "aguara check auto-detected node_modules and flagged event-stream@3.3.6"

# --- Case 2: aguara check --ci exits non-zero on compromised --------
# The README's CI usage promises `--ci` returns a non-zero exit code
# when a compromised package is present. Same fixture as Case 1.
case2_json="$OUT/smoke-v016-ci.json"
if /tmp/aguara --no-update-check check --path "$case1" --ci \
     --format json > "$case2_json" 2>&1; then
  cat "$case2_json"
  fail "aguara check --ci must exit non-zero when a compromised package is present"
fi
ok "aguara check --ci exited non-zero on compromised package"

# --- Case 3: aguara check --ci on a clean tree exits zero ----------
# Symmetric assertion: --ci must NOT trip on a clean project, or
# every CI build of every consumer's project breaks.
case3="$FIX_ROOT/clean"
mkdir -p "$case3/node_modules/lodash"
printf '{"name":"lodash","version":"4.17.21"}\n' \
  > "$case3/node_modules/lodash/package.json"

case3_json="$OUT/smoke-v016-ci-clean.json"
if ! /tmp/aguara --no-update-check check --path "$case3" --ci \
       --format json > "$case3_json"; then
  cat "$case3_json"
  fail "aguara check --ci on a clean tree must exit 0"
fi
if grep -Eq '"severity":[[:space:]]*"CRITICAL"' "$case3_json"; then
  cat "$case3_json"
  fail "aguara check --ci on a clean tree must produce no critical findings"
fi
ok "aguara check --ci on a clean tree exited 0 with no critical findings"

# --- Case 4: aguara status (no network) ----------------------------
# `aguara status` must work offline and produce a human-readable
# block with the embedded snapshot line. We do not assert the exact
# record count -- the snapshot regenerates each release -- only the
# structural markers.
status_out="$OUT/smoke-v016-status.txt"
/tmp/aguara --no-update-check status > "$status_out"

if ! grep -q "Threat intel:" "$status_out"; then
  cat "$status_out"
  fail "aguara status missing 'Threat intel:' header"
fi
if ! grep -q "Embedded" "$status_out"; then
  cat "$status_out"
  fail "aguara status missing 'Embedded' line"
fi
if ! grep -q "Default checks do not use the network" "$status_out"; then
  cat "$status_out"
  fail "aguara status missing offline-by-default disclosure"
fi
ok "aguara status produced the expected offline disclosure block"

# --- Case 5: aguara audit on the compromised fixture ---------------
# audit composes check + scan. With a known compromised package +
# no scan-side findings, the verdict status must be 'fail' and
# check_criticals must be > 0. JSON shape stable so dashboards can
# parse it.
audit_json="$OUT/smoke-v016-audit.json"
if /tmp/aguara --no-update-check audit "$case1" --ci \
     --format json -o "$audit_json"; then
  cat "$audit_json"
  fail "aguara audit --ci must exit non-zero on a compromised package"
fi
if ! grep -Eq '"status":[[:space:]]*"fail"' "$audit_json"; then
  cat "$audit_json"
  fail "aguara audit verdict.status must be 'fail' on the compromised fixture"
fi
if ! grep -Eq '"check_criticals":[[:space:]]*[1-9]' "$audit_json"; then
  cat "$audit_json"
  fail "aguara audit verdict.check_criticals must be >=1 on the compromised fixture"
fi
if ! grep -q '"check":' "$audit_json"; then
  cat "$audit_json"
  fail "aguara audit JSON missing .check sub-result"
fi
if ! grep -q '"scan":' "$audit_json"; then
  cat "$audit_json"
  fail "aguara audit JSON missing .scan sub-result"
fi
ok "aguara audit --ci surfaced compromised package, exited non-zero, JSON shape stable"

# --- Case 6: aguara audit on a clean tree --------------------------
clean_audit_json="$OUT/smoke-v016-audit-clean.json"
if ! /tmp/aguara --no-update-check audit "$case3" \
       --format json -o "$clean_audit_json"; then
  cat "$clean_audit_json"
  fail "aguara audit on a clean tree must exit 0"
fi
if ! grep -Eq '"status":[[:space:]]*"pass"' "$clean_audit_json"; then
  cat "$clean_audit_json"
  fail "aguara audit verdict.status must be 'pass' on the clean fixture"
fi
ok "aguara audit on a clean tree passed cleanly"

echo
echo "all v0.16 command smokes passed"
