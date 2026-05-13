#!/bin/sh
set -eu

OUT="${BENCH_OUT:-/out}"
COUNT="${BENCH_COUNT:-3}"
BENCHTIME="${BENCH_TIME:-1s}"

mkdir -p /tmp/go-build /tmp/go-tmp "$OUT"

run_capture() {
  label="$1"
  file="$2"
  shift 2

  echo "== $label =="
  if "$@" > "$file" 2>&1; then
    cat "$file"
  else
    status="$?"
    cat "$file"
    exit "$status"
  fi
  echo
}

echo "== Aguara benchmark =="
echo "output: $OUT"
echo "bench count: $COUNT"
echo "benchtime: $BENCHTIME"
echo

run_capture "go test ./..." "$OUT/go-test.txt" go test -count=1 ./...

run_capture "microbenchmarks: API" "$OUT/go-bench-api.txt" go test -run '^$' \
  -bench 'BenchmarkCached_(PlainText|StructuredMarkdown|JSONConfig|LargeContent|MixedWorkload)$' \
  -benchmem \
  -benchtime "$BENCHTIME" \
  -count "$COUNT" \
  .

run_capture "microbenchmarks: engines" "$OUT/go-bench-engines.txt" go test -run '^$' \
  -bench 'Benchmark(NLPAnalyzer|ScannerE2E)$' \
  -benchmem \
  -benchtime "$BENCHTIME" \
  -count "$COUNT" \
  ./internal/engine/nlp ./internal/scanner

run_capture "microbenchmarks: analyzers" "$OUT/go-bench-analyzers.txt" go test -run '^$' \
  -bench 'Benchmark(CITrustAnalyzer|PkgMetaAnalyzer|JSRiskAnalyzer|IncidentNPMCheck)$' \
  -benchmem \
  -benchtime "$BENCHTIME" \
  -count "$COUNT" \
  ./internal/engine/ci ./internal/engine/pkgmeta ./internal/engine/jsrisk ./internal/incident

echo "== build aguara =="
# Inject the same ldflags release builds use so the binary reports a
# real (Version, Commit) instead of the package defaults. AGUARA_VERSION
# and AGUARA_COMMIT come from the Dockerfile ARG/ENV pair populated by
# `make bench-docker` via `docker build --build-arg`.
PKG="github.com/garagon/aguara/cmd/aguara/commands"
LDFLAGS="-s -w -X ${PKG}.Version=${AGUARA_VERSION:-dev} -X ${PKG}.Commit=${AGUARA_COMMIT:-none}"
go build -trimpath -ldflags "$LDFLAGS" -o /tmp/aguara ./cmd/aguara
/tmp/aguara version > "$OUT/aguara-version.txt"
cat "$OUT/aguara-version.txt"
echo

# Emit a provenance record so downstream consumers (the maintainer or
# a CI gate) can verify the binary, image, and toolchain that produced
# the bench artifacts. Stays offline; no API calls.
{
  echo '{'
  printf '  "aguara_version": "%s",\n' "${AGUARA_VERSION:-dev}"
  printf '  "aguara_commit": "%s",\n' "${AGUARA_COMMIT:-none}"
  printf '  "go_version": "%s",\n' "$(go version | awk '{print $3}')"
  printf '  "docker_image": "%s",\n' "${DOCKER_IMAGE:-aguara-bench:local}"
  printf '  "timestamp_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "command": "%s"\n' "${BENCH_COMMAND:-benchmarks/run.sh}"
  echo '}'
} > "$OUT/provenance.json"
echo "wrote $OUT/provenance.json"
cat "$OUT/provenance.json"
echo

if [ -d testdata/real-skills ]; then
  echo "== corpus scan: testdata/real-skills =="
  /tmp/aguara --no-update-check scan --format json -o "$OUT/real-skills.json" testdata/real-skills
  go run ./benchmarks/cmd/benchsummary "$OUT/real-skills.json" > "$OUT/real-skills-summary.txt"
  cat "$OUT/real-skills-summary.txt"
else
  echo "testdata/real-skills not present; skipping corpus scan" > "$OUT/real-skills-summary.txt"
  cat "$OUT/real-skills-summary.txt"
fi

echo "== done =="
