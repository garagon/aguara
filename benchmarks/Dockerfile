# Benchmark image for Aguara.
#
# Build may need network to download Go modules, but the benchmark run is
# intended to execute with --network none via `make bench-docker`.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN adduser -D -u 10001 bench && chown -R bench:bench /src /go
USER bench

# AGUARA_VERSION / AGUARA_COMMIT are injected via `docker build --build-arg`
# so the binary built inside the image reports the same version + commit
# the host repo sees. Without these the binary defaults to "dev" / "none"
# and the provenance.json artifact loses traceability to the real revision.
ARG AGUARA_VERSION=dev
ARG AGUARA_COMMIT=none

ENV AGUARA_NO_UPDATE_CHECK=1 \
    NO_COLOR=1 \
    GOCACHE=/tmp/go-build \
    GOTMPDIR=/tmp/go-tmp \
    BENCH_OUT=/out \
    AGUARA_VERSION=$AGUARA_VERSION \
    AGUARA_COMMIT=$AGUARA_COMMIT

ENTRYPOINT ["/src/benchmarks/run.sh"]
