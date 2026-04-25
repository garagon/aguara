# Benchmark image for Aguara.
#
# Build may need network to download Go modules, but the benchmark run is
# intended to execute with --network none via `make bench-docker`.
FROM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN adduser -D -u 10001 bench && chown -R bench:bench /src /go
USER bench

ENV AGUARA_NO_UPDATE_CHECK=1 \
    NO_COLOR=1 \
    GOCACHE=/tmp/go-build \
    GOTMPDIR=/tmp/go-tmp \
    BENCH_OUT=/out

ENTRYPOINT ["/src/benchmarks/run.sh"]
