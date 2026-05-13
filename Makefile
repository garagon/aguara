BINARY := aguara
PKG := github.com/garagon/aguara
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -ldflags "-s -w -X $(PKG)/cmd/aguara/commands.Version=$(VERSION) -X $(PKG)/cmd/aguara/commands.Commit=$(COMMIT)"

# Reproducible provenance inputs for the Docker validation harness.
# git describe gives a tag-aware version (or "dev" outside a tagged
# build); rev-parse gives a 12-char short commit. Both can be
# overridden by the caller (release pipeline, CI gate) to pin to a
# specific revision.
AGUARA_VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
AGUARA_COMMIT      ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo none)
DOCKER_BENCH_IMAGE ?= aguara-bench:local
DOCKER_RACE_IMAGE  ?= aguara-race:local

DOCKER_RUN_FLAGS := --rm --network none --cap-drop ALL \
	--security-opt no-new-privileges --read-only \
	--tmpfs /tmp:rw,exec,nosuid,size=1g

.PHONY: build test lint run clean fmt vet wasm wasm-serve bench \
	bench-docker-image race-docker-image \
	bench-docker smoke-docker test-race-docker verify-docker

build:
	go build -trimpath $(LDFLAGS) -o $(BINARY) ./cmd/aguara

test:
	go test -race -count=1 ./...

bench:
	go test -run '^$$' -bench 'BenchmarkCached_(PlainText|StructuredMarkdown|JSONConfig|LargeContent|MixedWorkload)$$' -benchmem -count=3 .
	go test -run '^$$' -bench 'Benchmark(NLPAnalyzer|ScannerE2E)$$' -benchmem -count=3 ./internal/engine/nlp ./internal/scanner

bench-docker-image:
	docker build -f benchmarks/Dockerfile \
		--build-arg AGUARA_VERSION=$(AGUARA_VERSION) \
		--build-arg AGUARA_COMMIT=$(AGUARA_COMMIT) \
		-t $(DOCKER_BENCH_IMAGE) .

race-docker-image:
	docker build -f benchmarks/Dockerfile.race \
		--build-arg AGUARA_VERSION=$(AGUARA_VERSION) \
		--build-arg AGUARA_COMMIT=$(AGUARA_COMMIT) \
		-t $(DOCKER_RACE_IMAGE) .

bench-docker: bench-docker-image
	mkdir -p .bench
	docker run $(DOCKER_RUN_FLAGS) \
		-e DOCKER_IMAGE=$(DOCKER_BENCH_IMAGE) \
		-e BENCH_COMMAND="make bench-docker" \
		-v "$(CURDIR)/.bench:/out" $(DOCKER_BENCH_IMAGE)

test-race-docker: race-docker-image
	mkdir -p .bench
	docker run $(DOCKER_RUN_FLAGS) \
		-e DOCKER_IMAGE=$(DOCKER_RACE_IMAGE) \
		-e BENCH_COMMAND="make test-race-docker" \
		-v "$(CURDIR)/.bench:/out" $(DOCKER_RACE_IMAGE)

smoke-docker: bench-docker-image
	mkdir -p .bench
	docker run $(DOCKER_RUN_FLAGS) \
		--entrypoint /src/benchmarks/smoke-npm-incident.sh \
		-v "$(CURDIR)/.bench:/out" $(DOCKER_BENCH_IMAGE)
	docker run $(DOCKER_RUN_FLAGS) \
		--entrypoint /src/benchmarks/smoke-supply-chain.sh \
		-v "$(CURDIR)/.bench:/out" $(DOCKER_BENCH_IMAGE)

verify-docker: bench-docker test-race-docker smoke-docker
	@echo "verify-docker: all Docker validation targets passed"

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
