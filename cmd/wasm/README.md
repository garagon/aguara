# Browser rendering tests

This directory contains the bundled WASM example and its browser tests. Node
and Playwright are test dependencies only; the example has no new runtime
dependency.

From this directory, install the pinned test dependencies and Chromium:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npx --no-install playwright install chromium
npm test
```

The renderer tests supply controlled JSON at the WASM boundary and verify text
display, severity styles, scan options, errors, and tabs in Chromium. They block
unexpected requests and check that hostile result fields create no HTML nodes
or executable event handlers. Numeric-field cases are defensive rendering
checks, not claims that Go emits those fields as strings.

To include the real-engine integration test, build WASM from the repository
root and provide the matching Go runtime script:

```sh
GOMAXPROCS=2 GOMEMLIMIT=768MiB GOOS=js GOARCH=wasm \
  go build -p 1 -trimpath -o /tmp/aguara-ui-test.wasm ./cmd/wasm
cd cmd/wasm
AGUARA_WASM=/tmp/aguara-ui-test.wasm \
  AGUARA_WASM_EXEC="$(go env GOROOT)/lib/wasm/wasm_exec.js" npm test
```

Without `AGUARA_WASM`, the integration test is explicitly skipped. The WASM UI
workflow builds the binary and runs both test paths. Tests use one Chromium
instance and run sequentially; they are not fuzzing, load tests, or benchmarks.

## Promise lifecycle tests

The Go tests in this directory run as WASM under Node, not as native Go tests.
From the repository root:

```sh
GOMAXPROCS=1 GOMEMLIMIT=768MiB GOOS=js GOARCH=wasm \
  go test -p 1 -parallel 1 -run '^Test' -count=1 -timeout=30s \
  -exec "$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./cmd/wasm
```

They check Promise success, rejection, delayed completion, constructor failure,
and both scan entry points. A small captured object with a finalizer checks
that completed work is no longer held by the executor callback. Collection
checks are bounded; they do not measure heap growth or scan throughput. The
WASM UI workflow also runs these tests. `GOMAXPROCS=1` is required for Go's
single-threaded JS/WASM runtime; the race detector does not support this target.
