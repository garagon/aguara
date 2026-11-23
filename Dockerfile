# Base images pinned by multi-arch index digest for reproducible builds.
# Bump digests together with the tag when upgrading (e.g. alpine 3.22).
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# VERSION/COMMIT default to "dev"/"none" for local builds without --build-arg.
# CI passes the actual tag and commit so `aguara version` matches the release.
ARG VERSION=dev
ARG COMMIT=none

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/garagon/aguara/cmd/aguara/commands.Version=${VERSION} \
      -X github.com/garagon/aguara/cmd/aguara/commands.Commit=${COMMIT}" \
    -o /aguara ./cmd/aguara

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=builder /aguara /usr/local/bin/aguara

# Run as non-root to limit blast radius on container escape or arbitrary file write bugs.
RUN adduser -D -u 10001 aguara
USER aguara

ENTRYPOINT ["aguara"]
CMD ["scan", "."]
