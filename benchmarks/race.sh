#!/bin/sh
set -eu

OUT="${BENCH_OUT:-/out}"

mkdir -p /tmp/go-build /tmp/go-tmp "$OUT"

echo "== Aguara race test =="
echo "output: $OUT"
echo "go: $(go version)"
echo

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

run_capture "go test -race ./..." "$OUT/go-test-race.txt" \
  go test -race -count=1 ./...

# Emit a provenance record so race-detector runs are traceable to the
# same revision the bench image is. Format matches benchmarks/run.sh
# so downstream consumers can parse either artifact uniformly.
{
  echo '{'
  printf '  "aguara_version": "%s",\n' "${AGUARA_VERSION:-dev}"
  printf '  "aguara_commit": "%s",\n' "${AGUARA_COMMIT:-none}"
  printf '  "go_version": "%s",\n' "$(go version | awk '{print $3}')"
  printf '  "docker_image": "%s",\n' "${DOCKER_IMAGE:-aguara-race:local}"
  printf '  "timestamp_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "command": "%s"\n' "${BENCH_COMMAND:-benchmarks/race.sh}"
  echo '}'
} > "$OUT/provenance-race.json"
cat "$OUT/provenance-race.json"
echo

echo "== done =="
