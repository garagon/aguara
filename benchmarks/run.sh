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

echo "== build aguara =="
go build -trimpath -o /tmp/aguara ./cmd/aguara
/tmp/aguara version > "$OUT/aguara-version.txt"
cat "$OUT/aguara-version.txt"
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
