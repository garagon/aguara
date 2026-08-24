# Base images pinned by multi-arch index digest for reproducible builds.
# Bump digests together with the tag when upgrading (e.g. alpine 3.22).
FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder
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

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
COPY --from=builder /aguara /usr/local/bin/aguara

# Run as non-root to limit blast radius on container escape or arbitrary file write bugs.
RUN adduser -D -u 10001 aguara
USER aguara

ENTRYPOINT ["aguara"]
CMD ["scan", "."]
