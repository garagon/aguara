BINARY := aguara
PKG := github.com/garagon/aguara
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -ldflags "-s -w -X $(PKG)/cmd/aguara/commands.Version=$(VERSION) -X $(PKG)/cmd/aguara/commands.Commit=$(COMMIT)"

.PHONY: build test lint run clean fmt vet wasm wasm-serve bench bench-docker

build:
	go build -trimpath $(LDFLAGS) -o $(BINARY) ./cmd/aguara

test:
	go test -race -count=1 ./...

bench:
	go test -run '^$$' -bench 'BenchmarkCached_(PlainText|StructuredMarkdown|JSONConfig|LargeContent|MixedWorkload)$$' -benchmem -count=3 .
	go test -run '^$$' -bench 'Benchmark(NLPAnalyzer|ScannerE2E)$$' -benchmem -count=3 ./internal/engine/nlp ./internal/scanner

bench-docker:
	mkdir -p .bench
	docker build -f benchmarks/Dockerfile -t aguara-bench:local .
	docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,exec,nosuid,size=1g -v "$(CURDIR)/.bench:/out" aguara-bench:local

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

run:
	go run ./cmd/aguara $(ARGS)

wasm:
	GOOS=js GOARCH=wasm go build -trimpath -o aguara.wasm ./cmd/wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" .
	cp cmd/wasm/index.html .

wasm-serve: wasm
	@echo "Serving at http://localhost:8080"
	python3 -m http.server 8080

clean:
	rm -f $(BINARY) aguara.wasm wasm_exec.js index.html
