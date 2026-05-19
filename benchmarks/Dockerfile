# Benchmark image for Aguara.
#
# Build may need network to download Go modules, but the benchmark run is
# intended to execute with --network none via `make bench-docker`.
FROM golang:1.26-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d

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
