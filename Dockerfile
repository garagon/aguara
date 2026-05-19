# Base images pinned by multi-arch index digest for reproducible builds.
# Bump digests together with the tag when upgrading (e.g. alpine 3.22).
FROM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS builder
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

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
COPY --from=builder /aguara /usr/local/bin/aguara

# Run as non-root to limit blast radius on container escape or arbitrary file write bugs.
RUN adduser -D -u 10001 aguara
USER aguara

ENTRYPOINT ["aguara"]
CMD ["scan", "."]
